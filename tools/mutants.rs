use std::io::{self, Write};

// An empty anchor requires a unique match. Otherwise, replace the first match
// after the anchor. An empty replacement deletes the matched text.
type Patch = (&'static str, &'static str, &'static str);
type Mutant = (&'static str, &'static str, &'static str, &'static [Patch]);

// (name, category, source file key, patches)
const MUTANTS: &[Mutant] = &[
    ("M1-ogte-lte", "equiv", "allocator", &[(
        "",
        "if new_break < self.app_break() || new_break >= self.kernel_break() {",
        "if new_break <= self.app_break() || new_break >= self.kernel_break() {",
    )]),
    ("M2-space-flip", "l3", "allocator", &[(
        "",
        "if new_break < self.app_break() || new_break >= self.kernel_break() {",
        "if new_break < self.app_break() || new_break > self.kernel_break() {",
    )]),
    ("M3-drop-set-kernel-break", "h2", "allocator", &[(
        "",
        "            // We always allocate down, so we must lower the\n            // kernel_memory_break.\n            self.set_kernel_break(new_break);",
        "",
    )]),
    ("M4-align-mask", "l3", "allocator", &[(
        "",
        "let alignment_mask = !(align - 1);",
        "let alignment_mask = !align;",
    )]),
    ("M5-align-no-min", "panic", "allocator", &[(
        "",
        "let align = max_usize(align, 2);",
        "let align = align;",
    )]),
    ("M6-hwm-no-max", "h2", "allocator", &[(
        "",
        "            let new_water_mark = max_ptr(self.breaks.high_water_mark, buf_end_addr);\n            self.breaks.high_water_mark = new_water_mark;\n            Ok(())\n        } else {\n            Err(())",
        "            let new_water_mark = buf_end_addr;\n            self.breaks.high_water_mark = new_water_mark;\n            Ok(())\n        } else {\n            Err(())",
    )]),
    ("M7-update-drop-hwm-check", "underflow", "allocator", &[(
        "",
        "            || new_app_break.as_usize() < high_water_mark.as_usize()",
        "",
    )]),
    ("M8-update-no-ab-write", "h2", "allocator", &[(
        "",
        "        let old_break = self.breaks.app_break;\n        self.breaks.app_break = FluxPtrU8::from(new_app_break);",
        "        let old_break = self.breaks.app_break;",
    )]),
    ("M9-update-drop-oom-recheck", "equiv", "allocator", &[(
        "",
        "        if new_app_break > kernel_break.as_usize() {\n            return Err(Error::OutOfMemory);\n        }",
        "",
    )]),
    ("MP1-alloc-drop-zero-check", "l3", "mpu", &[(
        "fn allocate_regions",
        "if region_size > available_size || region_size == 0 {",
        "if region_size > available_size {",
    )]),
    ("MP2-alloc-rnum-off", "blind", "mpu", &[(
        "fn allocate_regions",
        "region_number: max_region_number - 1,",
        "region_number: max_region_number,",
    )]),
    ("MP3-create-start-off", "l3", "mpu", &[(
        "",
        "start: Some(start),\n            size: Some(size),",
        "start: Some(start.wrapping_add(1)),\n            size: Some(size),",
    )]),
    ("MP4-update-strict", "equiv", "mpu", &[(
        "fn update_regions",
        "if region_size > available_size || region_size == 0 {",
        "if region_size >= available_size || region_size == 0 {",
    )]),
];

fn json_string(out: &mut impl Write, value: &str) -> io::Result<()> {
    write!(out, "\"")?;
    for ch in value.chars() {
        match ch {
            '"' => write!(out, "\\\"")?,
            '\\' => write!(out, "\\\\")?,
            '\x00'..='\x1f' => write!(out, "\\u{:04x}", u32::from(ch))?,
            _ => write!(out, "{ch}")?,
        }
    }
    write!(out, "\"")
}

fn main() -> io::Result<()> {
    let mut out = io::BufWriter::new(io::stdout().lock());
    write!(out, "[")?;
    for (i, &(name, category, source, patches)) in MUTANTS.iter().enumerate() {
        if i != 0 {
            write!(out, ",")?;
        }
        write!(out, "[")?;
        for value in [name, category, source] {
            json_string(&mut out, value)?;
            write!(out, ",")?;
        }
        write!(out, "[")?;
        for (j, &(anchor, old, new)) in patches.iter().enumerate() {
            if j != 0 {
                write!(out, ",")?;
            }
            write!(out, "[")?;
            if !anchor.is_empty() {
                json_string(&mut out, &format!("@{anchor}"))?;
                write!(out, ",")?;
            }
            json_string(&mut out, old)?;
            write!(out, ",")?;
            json_string(&mut out, new)?;
            write!(out, "]")?;
        }
        write!(out, "]]")?;
    }
    writeln!(out, "]")?;
    out.flush()
}
