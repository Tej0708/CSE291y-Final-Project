#!/usr/bin/env python3
"""Spec census for tock-flux: extract every flux_rs::sig / invariant / refined_by
attribute and classify its translatability into a fuzz harness (H3).

Usage: python3 spec_census.py <repo-root> <out.csv>
"""
import csv, re, sys, os

# Reason codes (see experiment-plan.md §4)
GHOST_PARAM = "GHOST-PARAM"        # ghost refinement params (@b, [b.breaks....]) not runtime-observable
HIGHER_ORDER = "HIGHER-ORDER"      # references trait assoc fns (R::..., Self::...)
STRG = "STRG-OWNERSHIP"            # &strg Self strong-update spec; needs snapshot oracle
EXISTENTIAL = "EXISTENTIAL"        # existentials / bounded choice in return refinement
TRUSTED = "TRUSTED-IMPL"           # trusted boundary (hardware MPU impl, lemmas)
NO_RUNTIME = "NO-RUNTIME"          # FluxPtr needs backing memory (partial: solvable)
FULLY = "fully"
PARTIAL = "partial"
UNTRANS = "untranslatable"

def parse_attrs(text):
    """Yield (kind, body, line) for each #[flux_rs::sig(...)] / invariant / refined_by."""
    results = []
    i = 0
    line = 1
    while i < len(text):
        c = text[i]
        if c == "\n":
            line += 1
            i += 1
            continue
        m = re.match(r"#\[flux_rs::(sig|invariant|refined_by|assoc)\s*\(", text[i:])
        if not m:
            i += 1
            continue
        start_line = line
        kind = m.group(1)
        j = i + m.end()  # position after '('
        depth = 1
        while j < len(text) and depth > 0:
            if text[j] == "(":
                depth += 1
            elif text[j] == ")":
                depth -= 1
            elif text[j] == "\n":
                line += 1
            j += 1
        body = text[i + m.end(): j - 1].strip()
        results.append((kind, body, start_line, j))  # j = index after closing paren
        i = j
    return results

def fn_name_after(text, idx):
    """Find the name of the item (fn/struct/trait) following position idx."""
    rest = text[idx: idx + 3000]
    m = re.search(r"\bfn\s+([A-Za-z_][A-Za-z0-9_]*)", rest)
    if m:
        # make sure no 'struct'/'trait' keyword comes first
        ms = re.search(r"\b(struct|trait|impl|enum)\s+([A-Za-z_][A-Za-z0-9_]*)", rest[: m.start()])
        if ms:
            return ms.group(2), "type"
        return m.group(1), "fn"
    m = re.search(r"\b(struct|trait|impl|enum)\s+([A-Za-z_][A-Za-z0-9_]*)", rest)
    if m:
        return m.group(2), "type"
    return "?", "?"

def classify(kind, body, item, is_impl_lemma, in_trait_default_impl):
    tags = []
    if kind in ("invariant", "refined_by"):
        tags.append("refinement-decl")  # not a function spec; graded by usage
        return "n/a", "REFINEMENT-DECL", ";".join(tags)
    if is_impl_lemma:
        return UNTRANS, "TRUSTED-IMPL", "impl-method of trait (hardware/lemma side)"
    reasons = []
    if re.search(r"::(is_set|overlaps|start|size|rnum|perms|region_can_access_exactly|regions_can_access_exactly|no_region_overlaps_app_block|create_exact_region|allocate_regions|update_regions|default)\b", body):
        reasons.append("assoc-fn-call")
    if re.search(r"\b(forall|exists)\b", body):
        reasons.append("quantifier")
    if "strg" in body:
        reasons.append("strg-ownership")
    if re.search(r"\[\w+\.|\[@\w+\]|@\w+", body):
        reasons.append("ghost-param")
    if "lemma" in item:
        reasons.append("lemma-fn")
    if re.search(r"\{\w+\.\s|\{\w+\.\s*\|", body) or re.search(r"->\s*Self\s*\{", body):
        reasons.append("existential-return")
    if "FluxPtrU8" in body or "FluxPtrU8Mut" in body or "FluxPtr" in body:
        reasons.append("uses-FluxPtr")
    if not reasons:
        return FULLY, "NONE", "pure value predicate"
    tags.extend(reasons)
    hard = {"quantifier", "assoc-fn-call", "lemma-fn"}
    if "lemma-fn" in reasons:
        return UNTRANS, "TRUSTED-IMPL", ";".join(tags)
    if reasons and set(reasons) <= {"uses-FluxPtr", "ghost-param", "strg-ownership", "existential-return"}:
        return PARTIAL, ";".join(reasons), ";".join(tags)
    if "assoc-fn-call" in reasons or "quantifier" in reasons:
        # assoc-fn calls on R are executable for a concrete impl; ghost math is simulable
        return PARTIAL, ";".join(reasons), ";".join(tags)
    return PARTIAL, ";".join(reasons), ";".join(tags)

def main():
    repo = sys.argv[1]
    out = sys.argv[2]
    rows = []
    for dirpath, _, files in os.walk(os.path.join(repo, "kernel", "src")):
        for f in sorted(files):
            if not f.endswith(".rs"):
                continue
            path = os.path.join(dirpath, f)
            rel = os.path.relpath(path, repo)
            text = open(path, encoding="utf-8").read()
            # Track whether we are inside a `impl RegionDescriptor for X` block (trusted impl side)
            attrs = parse_attrs(text)
            for kind, body, line, endidx in attrs:
                item, itype = fn_name_after(text, endidx)
                # find enclosing impl region type: crude check — search backwards for "impl RegionDescriptor for"
                before = text[:endidx]
                impl_match = None
                for m in re.finditer(r"impl\s+RegionDescriptor\s+for\s+(\w+)", before):
                    impl_match = m.group(1)
                in_impl = impl_match is not None and before.count("}") >= 0
                # crude: is the item inside that impl block? check braces nesting is complex; use heuristic:
                # impl region must start before and the item appears before the next "pub trait" after it
                is_impl = False
                if impl_match and impl_match not in ("MpuRegionDefault",):
                    # MpuRegionDefault is the software impl we CAN test
                    seg = before[before.rfind(f"impl RegionDescriptor for {impl_match}"):]
                    is_impl = seg.count("{") > seg.count("}") - 1
                cls, reason, tags = classify(kind, body, item, is_impl, False)
                rows.append({
                    "file": rel, "line": line, "kind": kind, "item": item, "item_type": itype,
                    "class": cls, "reason": reason, "tags": tags,
                    "spec": re.sub(r"\s+", " ", body)[:400],
                })

    # ---- manual review overrides (second pass, 2026-10-25) ----
    # key: (file, line, item) -> (class, reason, note)
    OVERRIDES = {
        # trait-MPU methods on `impl MPU for ()`: no-op hardware boundary
        ("kernel/src/platform/mpu.rs", 618, "enable_app_mpu"): (PARTIAL, "TRUSTED-IMPL", "no-op on impl MPU for (); spec has no observable postcondition"),
        ("kernel/src/platform/mpu.rs", 623, "disable_app_mpu"): (PARTIAL, "TRUSTED-IMPL", "no-op on impl MPU for (); spec has no observable postcondition"),
        # requires real process buffers / kernel state to construct
        ("kernel/src/grant.rs", 956, "update_saved_allow_rw"): (PARTIAL, "NO-RUNTIME", "needs ReadWriteProcessBuffer + grant state"),
        ("kernel/src/grant.rs", 1029, "new_inner"): (PARTIAL, "NO-RUNTIME", "constructor with GrantDataAlign; needs full grant infra"),
        ("kernel/src/process_loading.rs", 356, "load_process"): (PARTIAL, "NO-RUNTIME", "generic over Process trait; needs loader infra"),
        ("kernel/src/process_standard.rs", 1294, "create"): (PARTIAL, "NO-RUNTIME", "needs full process creation infra"),
        ("kernel/src/process_binary.rs", 141, "create"): (PARTIAL, "NO-RUNTIME", "needs TockBinary + process binary layout"),
        ("kernel/src/process_loading.rs", 285, "discover_process_binary"): (PARTIAL, "NO-RUNTIME", "needs flash region backing"),
        ("kernel/src/process_loading.rs", 546, "find_open_process_binary_slot"): (PARTIAL, "NO-RUNTIME", "needs Processes struct"),
        ("kernel/src/grant.rs", 365, "calc_padding"): (FULLY, "NONE", "pure function; oracle = 0 < n < align"),
    }
    for r in rows:
        k = (r["file"], r["line"], r["item"])
        if k in OVERRIDES:
            cls, reason, note = OVERRIDES[k]
            r["class"], r["reason"] = cls, reason
            r["tags"] = (r["tags"] + " | reviewed: " + note)[:300]
        # lemma specs: also mark the 5 trait-decl lemmas (mpu.rs <320) as untranslatable
        if "lemma" in r["item"] and r["class"] != "untranslatable":
            r["class"], r["reason"] = UNTRANS, "TRUSTED-IMPL"
            r["tags"] = (r["tags"] + " | reviewed: proof lemma, empty runtime body")[:300]

    with open(out, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    # summary
    from collections import Counter
    c = Counter((r["kind"], r["class"]) for r in rows)
    print(f"total attrs: {len(rows)}")
    for (k, cl), n in sorted(c.items()):
        print(f"  {k:12s} {cl:16s} {n}")
    print(f"\nwritten {out}")

if __name__ == "__main__":
    main()
