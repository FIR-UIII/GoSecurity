# Go AppSec: `unsafe` & CGo Anti-Patterns

> **Priority: understand how NOT to do it — and why.**

Each example contains:
- **ANTI-PATTERN** — vulnerable code with a real CWE mapping and explanation of the attack
- **SAFE** — the correct Go idiom and why it prevents the vulnerability

---

## Examples

| # | Topic | CWE | Core risk |
|---|-------|-----|-----------|
| [01](01_type_confusion/) | Type confusion via `unsafe.Pointer` | CWE-843 | Reinterpret struct memory → privilege escalation |
| [02](02_buffer_overflow/) | Heap over-read/write via `unsafe.Slice` | CWE-125, CWE-787 | Lie about slice length → Heartbleed-style leak |
| [03](03_cgo_use_after_free/) | Use-after-free via CGo | CWE-416 | C stores Go pointer → dangling ref after GC |
| [04](04_cgo_memory_leak/) | Memory leak via CGo | CWE-401 | `C.CString` without `C.free` → heap exhaustion |
| [05](05_integer_overflow/) | Integer overflow → unsafe access | CWE-190, CWE-680 | Negative/overflowed length bypasses bounds |
| [06](06_cgo_injection/) | Command injection via CGo | CWE-78 | User input to C `system()` → arbitrary execution |

---

## Running

```bash
# Prerequisites: Go 1.21+, C compiler (macOS: xcode-select --install)

# Run a single example
go run ./01_type_confusion/

# Example 03 with strict CGo pointer checking (panics on the anti-pattern)
GOEXPERIMENT=cgocheck2 go run ./03_cgo_use_after_free/
```

---

## Key rules to remember

### `unsafe` package

| Pattern | Risk | Safe replacement |
|---------|------|-----------------|
| `*(*T)(unsafe.Pointer(&x))` | Type confusion, struct field bypass | Use `math.Float64bits`, `encoding/binary` |
| `unsafe.Slice(ptr, n)` with unvalidated `n` | Heap over-read / panic | Validate: `n >= 0 && n <= len(buf)` first |
| `base := uintptr(unsafe.Pointer(p))` across statements | Dangling pointer after GC | Keep the conversion inside a single expression |

### CGo pointer rules

| Rule | Why |
|------|-----|
| Never let C store a Go pointer past the call boundary | Go GC may move or free the object → use-after-free |
| Always `defer C.free(...)` after `C.CString` / `C.CBytes` / `C.malloc` | Go GC ignores C heap → leak |
| Never pass user input to C shell functions (`system`, `popen`) | Shell metacharacters → command injection |

### Safe alternatives

| Unsafe idiom | Safe replacement |
|---|---|
| Go pointer stored in C global | `C.CString` (copy to C heap) or `runtime.Pinner` (pin Go memory) |
| `C.CString` alone | `cstr := C.CString(s); defer C.free(unsafe.Pointer(cstr))` |
| `system(userInput)` in C | `exec.Command(name, args...)` — no shell, no injection |
| `int32` length cast to `uint` | Check `n >= 0` before widening; use `int64` for multiplication |
