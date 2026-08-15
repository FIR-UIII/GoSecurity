// TOPIC: Memory Leak via CGo — Forgetting C.free
// CWE-401: Missing Release of Memory after Effective Lifetime
//
// C.CString, C.CBytes, and C.malloc allocate memory with malloc on the C heap.
// Go's garbage collector has ZERO visibility into C heap allocations.
// Losing the pointer without calling C.free leaks that memory forever.
//
// In a long-running service each leaked call accumulates until the process OOMs
// or the OS kills it.
//
// Run: go run ./04_cgo_memory_leak/

package main

/*
#include <stdlib.h>
#include <string.h>

size_t c_strlen(const char* s) { return strlen(s); }
void   c_use_bytes(const void* p, size_t n) { (void)p; (void)n; }
*/
import "C"
import (
	"fmt"
	"unsafe"
)

// ── ANTI-PATTERNS ─────────────────────────────────────────────────────────────

// antipatternLeakCString leaks a C string on every call.
// C.CString → malloc; without C.free the allocation outlives the function.
// Call this in a loop and the process heap grows without bound.
func antipatternLeakCString(s string) C.size_t {
	cstr := C.CString(s) // malloc ~len(s)+1 bytes on the C heap
	// ← MISSING: defer C.free(unsafe.Pointer(cstr))
	return C.c_strlen(cstr) // cstr escapes; never freed
}

// antipatternLeakCBytes leaks a C byte buffer.
// Returning unsafe.Pointer to the caller makes it trivially easy to forget
// that the caller is now responsible for calling C.free.
func antipatternLeakCBytes(data []byte) unsafe.Pointer {
	ptr := C.CBytes(data) // malloc len(data) bytes
	// ← caller must C.free(ptr) — easy to forget, not enforced by type system
	return ptr
}

// antipatternLeakCMalloc allocates directly but forgets to free on error path.
func antipatternLeakCMalloc(size int) {
	ptr := C.malloc(C.size_t(size))
	if ptr == nil {
		return // good: nothing to free
	}
	// ... do work ...
	if size > 100 {
		fmt.Println("ANTI-PATTERN | Early return without C.free → leak!")
		return // BAD: ptr leaks on this branch
	}
	C.free(ptr) // only reached when size <= 100
}

// ── SAFE ALTERNATIVES ─────────────────────────────────────────────────────────

// safeUseCString always pairs C.CString with a deferred C.free.
// defer fires even on panic, so the memory is freed on every exit path.
func safeUseCString(s string) C.size_t {
	cstr := C.CString(s)
	defer C.free(unsafe.Pointer(cstr)) // ← freed on every return path, including panic

	return C.c_strlen(cstr)
}

// safeUseCBytes wraps C heap memory in a closure: the buffer is freed
// when fn returns, so the caller never holds a raw unsafe.Pointer.
func safeUseCBytes(data []byte, fn func(unsafe.Pointer, int)) {
	ptr := C.CBytes(data)
	defer C.free(ptr) // C.CBytes returns unsafe.Pointer directly — no cast needed

	fn(ptr, len(data))
}

// safeCMalloc frees on every path including the error branch.
func safeCMalloc(size int) {
	ptr := C.malloc(C.size_t(size))
	if ptr == nil {
		fmt.Println("SAFE         | C.malloc returned nil (OOM)")
		return // nothing allocated — nothing to free
	}
	defer C.free(ptr) // ← covers ALL subsequent return paths

	C.c_use_bytes(ptr, C.size_t(size))
	fmt.Printf("SAFE         | allocated and freed %d C bytes at %p\n", size, ptr)
}

func main() {
	fmt.Println("=== 04: Memory Leak via CGo ===")
	fmt.Println()

	s := "leaking string"
	n := antipatternLeakCString(s)
	fmt.Printf("ANTI-PATTERN | strlen=%d, but malloc for %q was NEVER freed\n", n, s)

	leaked := antipatternLeakCBytes([]byte{1, 2, 3})
	fmt.Printf("ANTI-PATTERN | C buffer at %p leaked (no C.free called)\n", leaked)
	// caller would need to C.free(leaked) here — easy to forget

	antipatternLeakCMalloc(200) // hits the early-return leak branch
	fmt.Println()

	n = safeUseCString(s)
	fmt.Printf("SAFE         | strlen=%d, C string freed via defer\n", n)

	safeUseCBytes([]byte{1, 2, 3}, func(p unsafe.Pointer, n int) {
		fmt.Printf("SAFE         | using %d-byte C buffer at %p\n", n, p)
	})

	safeCMalloc(256)
}
