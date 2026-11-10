# Kernel patch for fuzzing enablement

Apply these changes to a clean `tock-flux` checkout to build the fuzz crate.
None of them change kernel semantics in non-fuzz builds; the entire shim is
gated on `#[cfg(fuzzing)]`, which cargo-fuzz sets automatically (and which is
never set for normal or `cargo flux` builds).

## 1. New file: `kernel/src/fuzz_shim.rs`

Copy `fuzz_shim.rs` from this directory to `kernel/src/fuzz_shim.rs`.

It re-exports the `pub(crate)` allocator internals behind a public API
(type aliases + thin wrapper functions) and provides the runtime-executable
AppBreaks invariant checker and the state `Snapshot` used by the oracles.

## 2. `kernel/src/lib.rs`

After the private module declarations (the `mod config; … mod syscall_driver;`
block), add:

```diff
 mod syscall_driver;
+
+// Fuzz-harness shim: public re-exports of pub(crate) allocator internals,
+// compiled only under `--cfg fuzzing` (set by cargo-fuzz builds).
+#[cfg(fuzzing)]
+pub mod fuzz_shim;
```

## 3. `kernel/src/allocator.rs` — visibility only (4 lines)

Required because `pub type` aliases in the shim cannot name `pub(crate)`
types, and the fuzz crate constructs `AppMemoryAllocator` generically:

```diff
-pub(crate) enum AllocateAppMemoryError {
+pub enum AllocateAppMemoryError {

-pub(crate) struct AppBreaks {
+pub struct AppBreaks {

-pub(crate) struct AppMemoryAllocator<R: RegionDescriptor + Display + Copy> {
+pub struct AppMemoryAllocator<R: RegionDescriptor + Display + Copy> {

     #[flux_rs::sig(fn (&Self) -> Option<{idx. usize[idx] | idx > 2 && idx < 8}>)]
-    fn next_available_ipc_idx(&self) -> Option<usize> {
+    pub(crate) fn next_available_ipc_idx(&self) -> Option<usize> {
```

(Flux signatures are untouched; `cargo flux` still checks these items.)

## 4. Workspace `Cargo.toml`

```diff
-exclude = ["tools/"]
+exclude = ["tools/", "fuzz/"]
```

## 5. The fuzz crate

Copy the `fuzz/` directory from this package to `<tock-flux>/fuzz/`.
It is its own workspace and does not affect the kernel workspace build.

Then:

```bash
export CARGO_TARGET_DIR=/tmp/fuzz-target   # local disk!
export AR=<rustup-toolchain>/lib/rustlib/x86_64-unknown-linux-gnu/bin/llvm-ar
cd fuzz && cargo fuzz build --sanitizer none
```
