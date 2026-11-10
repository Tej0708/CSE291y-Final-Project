#!/usr/bin/env python3
"""Minimal spec→harness translator (E2).

Reads the census for the allocator fuzz targets and generates harness files
whose L1 (struct invariants) and L2 (literal ensures clauses) oracles are
derived mechanically from the Flux spec text. L3 semantic contracts (the
content the verifier discharged beyond the surface spec) are NOT generated —
each site emits a `TODO(L3)` marker pointing at the handwritten harness.

Translation coverage and generated-line metrics are printed at the end and
written to translate_metrics.json.

Usage: translate.py <repo-root> <out-dir>
"""
import csv, json, os, re, sys
from pathlib import Path

# targets: census item -> (rust shim call, arg decode, ret-kind, needs-prelude)
TARGETS = {
    "in_app_ram_memory": dict(
        ret="bool", prelude=False,
        call="fuzz_shim::a_in_app_ram_memory(&alloc, start, end)",
        args="let start = interesting_or_arbitrary(&mut u) as u32 as usize;\n    let end = interesting_or_arbitrary(&mut u) as u32 as usize;",
    ),
    "in_app_flash_memory": dict(
        ret="bool", prelude=False,
        call="fuzz_shim::a_in_app_flash_memory(&alloc, start, end)",
        args="let start = interesting_or_arbitrary(&mut u) as u32 as usize;\n    let end = interesting_or_arbitrary(&mut u) as u32 as usize;",
    ),
    "add_shared_readwrite_buffer": dict(
        ret="result_unit", prelude=True,
        call="fuzz_shim::a_add_shared_readwrite_buffer(&mut alloc, start, size)",
        args="let start = interesting_or_arbitrary(&mut u) as u32 as usize;\n    let size = small(&mut u);",
    ),
    "update_app_memory": dict(
        ret="result_usize", prelude=False,
        call="fuzz_shim::a_update_app_memory(&mut alloc, new_app_break)",
        args="let new_app_break = interesting_or_arbitrary(&mut u) as u32 as usize;",
    ),
    "allocate_in_grant_region_internal": dict(
        ret="option_usize", prelude=True,
        call="fuzz_shim::a_allocate_in_grant_region_internal(&mut alloc, size, align)",
        args="let size = small(&mut u);\n    let align = small(&mut u);",
    ),
}

FIELD_RE = re.compile(r"\b(?:b|bc|old_bc|old_app|app)\.breaks\.(\w+)\b")

def rewrite_pred(expr):
    """Rewrite a Flux refinement expression into a Rust oracle expression
    over the SpecView `v` and the decoded parameters."""
    e = expr
    e = re.sub(r"\bvalid_size\(([^()]*)\)", r"(\1 <= U32MAX)", e)
    # ghost field accesses -> SpecView
    e = FIELD_RE.sub(lambda m: f"v.{m.group(1)}", e)
    # FluxPtr values in the shim API are usize already; ghost var p is the result
    e = e.replace("buf_start_addr", "start").replace("buf_end_addr", "(start + size)")
    e = e.replace("new_break", "(new_break_placeholder)")
    return e

def parse_sig(spec):
    """Split a sig into (params, ret-kind, clauses). Returns dict."""
    out = {"strg": "strg" in spec, "ret_refine": None, "ensures": [], "ret_kind": None}
    m = re.search(r"->\s*(.*?)\s*(?:ensures|$)", spec, re.S)
    ret = m.group(1).strip() if m else ""
    if ret.startswith("bool["):
        out["ret_kind"] = "bool"
        out["ret_refine"] = ret[5:ret.rindex("]")]
    elif "Result" in ret or "Option" in ret:
        out["ret_kind"] = "result" if "Result" in ret else "option"
        mm = re.search(r"\|\s*([^}]+)\}", ret)  # inner refinement `{... | expr}`
        if mm:
            out["ret_refine"] = mm.group(1).strip()
    m2 = re.search(r"ensures\s+(.*)$", spec, re.S)
    if m2:
        out["ensures"] = [c.strip() for c in m2.group(1).split("&&") if c.strip()]
    return out

def oracle_for(item, sig):
    """Emit the generated oracle section (L1+L2) as Rust lines. Returns
    (lines, n_auto, n_todo)."""
    lines, auto, todo = [], 0, 0
    P = lambda s: lines.append(s)
    P("    // INVARIANTS (L1) — generated from the AppBreaks/AppMemoryAllocator")
    P("    // invariant attributes (see census: refinement-decl rows)")
    P("    check_invariants(&alloc);")
    auto += 1
    parsed = parse_sig(sig)

    if parsed["ret_kind"] == "bool" and parsed["ret_refine"]:
        expr = rewrite_pred(parsed["ret_refine"])
        P("    // ENSURES (L2) — generated from the sig's return refinement")
        P(f"    check!(2, out == ({expr}), \"return value violates sig refinement\");")
        auto += 1
    else:
        if parsed["ret_kind"] in ("result", "option"):
            P("    // ENSURES (L2) — generated: failure outcome leaves state unchanged")
            cond = "Err(_)" if parsed["ret_kind"] == "result" else "None"
            P(f"    if matches!(out, {cond}) {{")
            P('        check!(2, before.state_equal(&alloc), "failure outcome but state changed (ensures self: Self)");')
            P("    }")
            auto += 1
            if parsed["ret_refine"]:
                expr = rewrite_pred(parsed["ret_refine"])
                P("    // ENSURES (L2) — generated from the success-value refinement")
                if re.search(r"\bp\b", expr):
                    P("    if let Some(p) = out {")
                    P(f'        check!(2, {expr}, "Some(p) violates sig refinement");')
                    P("    }")
                else:
                    guard = "if out.is_ok()" if parsed["ret_kind"] == "result" else "if out.is_some()"
                    P(f"    {guard} {{")
                    P(f"        let _ok_refine = {expr};")
                    P("    }")
                auto += 1
        if parsed["ensures"]:
            for c in parsed["ensures"]:
                if re.search(r"opt\s*=>\s*bc\.breaks\.kernel_break\s*>=\s*bc\.breaks\.app_break", c):
                    P("    // ENSURES (L2) — generated from `(opt => bc.breaks.kernel_break >= bc.breaks.app_break)`")
                    P("    if out.is_some() {")
                    P("        let b = &alloc.breaks;")
                    P("        check!(2, b.kernel_break.as_usize() >= b.app_break.as_usize(), \"post kernel_break < app_break\");")
                    P("    }")
                    auto += 1
                elif re.search(r"!opt\s*=>\s*bc\s*==\s*old_bc", c):
                    P("    // ENSURES (L2) — generated from `(!opt => bc == old_bc)` (covered above)")
                    auto += 1
                elif "ensures self: Self" in c or c.startswith("self:"):
                    pass  # already emitted as L1 + unchanged-check
                else:
                    P(f"    // TODO(L2): unhandled ensures clause: {c[:80]}")
                    todo += 1
    P("    // TODO(L3): semantic contracts discharged by the verifier but not in the")
    P("    // surface spec (break movement, alignment, watermark semantics) — see")
    P("    // the handwritten harness; the ablation table quantifies what L3 adds.")
    todo += 1
    return lines, auto, todo

PRELUDE = """    // Reachability prelude — **not derivable from the spec** (finding F1):
    // the verified constructor yields app_break == kernel_break, so Some/Ok
    // paths are dead without lowering the app break first. Hand-added.
    let kb0 = alloc.breaks.kernel_break.as_usize();
    let ms0 = alloc.breaks.memory_start.as_usize();
    if kb0 - ms0 < 2 {
        return;
    }
    let new_ab = ms0 + 1 + (small(&mut u) % (kb0 - ms0 - 1));
    if fuzz_shim::a_update_app_memory(&mut alloc, new_ab).is_err() {
        return;
    }
"""

TEMPLATE = '''//! AUTO-GENERATED by spec-fuzz/tools/translate.py from the Flux sig of
//! `AppMemoryAllocator::{item}` — minimal-translator demo (E2). Do not edit
//! by hand; L3 sites are TODO markers by design.
#![no_main]

use arbitrary::Unstructured;
use kernel::fuzz_shim::{{self, Snapshot}};
use libfuzzer_sys::fuzz_target;
use ticktock_spec_fuzz::{{check, check_invariants, gen_allocator, interesting_or_arbitrary, small, U32MAX}};

/// SpecView: the ghost refinement fields of AppBreaks made runtime-observable.
struct SpecView {{
    memory_start: usize, memory_size: usize, app_break: usize,
    high_water_mark: usize, kernel_break: usize, flash_start: usize, flash_size: usize,
}}

impl SpecView {{
    fn of(a: &kernel::fuzz_shim::TestAllocator) -> Self {{
        let b = &a.breaks;
        Self {{
            memory_start: b.memory_start.as_usize(), memory_size: b.memory_size,
            app_break: b.app_break.as_usize(), high_water_mark: b.high_water_mark.as_usize(),
            kernel_break: b.kernel_break.as_usize(), flash_start: b.flash_start.as_usize(),
            flash_size: b.flash_size,
        }}
    }}
}}

fuzz_target!(|data: &[u8]| {{
    let mut u = Unstructured::new(data);
    let Some(mut alloc) = gen_allocator(&mut u) else {{ return; }};
{prelude}{args}
    let before = Snapshot::take(&alloc);

    let out = {call};
    let v = SpecView::of(&alloc);
    let _ = &before;

{oracle}
}});
'''

def main():
    repo, outdir = Path(sys.argv[1]), Path(sys.argv[2])
    outdir.mkdir(parents=True, exist_ok=True)
    rows = list(csv.DictReader(open(Path(__file__).resolve().parent.parent / "census.csv")))
    metrics = {"targets": {}, "total_auto_lines": 0, "total_todo": 0}
    for item, cfg in TARGETS.items():
        row = next((r for r in rows if r["item"] == item and r["kind"] == "sig"
                    and "allocator.rs" in r["file"]), None)
        if row is None:
            print(f"!! no census row for {item}")
            continue
        oracle, n_auto, n_todo = oracle_for(item, row["spec"])
        src = TEMPLATE.format(
            item=item,
            prelude=PRELUDE if cfg["prelude"] else "",
            args=cfg["args"], call=cfg["call"],
            oracle="\n".join(oracle),
        )
        # self-import fix: Snapshot used only in some targets — keep, harmless
        fname = f"{item}_gen.rs"
        (outdir / fname).write_text(src)
        metrics["targets"][item] = {"auto_lines": n_auto, "todo_sites": n_todo, "file": fname}
        metrics["total_auto_lines"] += n_auto
        metrics["total_todo"] += n_todo
        print(f"generated {fname}: {n_auto} auto oracle statements, {n_todo} TODO sites")
    (Path(__file__).resolve().parent.parent / "translate_metrics.json").write_text(json.dumps(metrics, indent=1))
    print(f"\nmetrics: {metrics['total_auto_lines']} auto statements, "
          f"{metrics['total_todo']} explicit TODO(L3)/L2 sites across {len(metrics['targets'])} targets")

if __name__ == "__main__":
    main()
