// TOPIC: Use-After-Free via CGo — Go GC vs C Pointer Lifetime
// CWE-416: Use After Free
//
// CGo pointer-passing rule (from `go help cgo`):
//   "C code may not keep a copy of a Go pointer after the call returns."
//
// Go's GC may move or reclaim Go-managed memory at any time once it is
// no longer reachable from Go. If C has stored a Go pointer, it now
// holds a dangling reference — reading it is use-after-free.
//
// Detection:
//   Default (GOEXPERIMENT=cgocheck, cgocheck=1): checks pointer-in-pointer rules
//   Strict  (GOEXPERIMENT=cgocheck2):            also detects stored Go pointers → panics
//   Disable (GONOSANITY / CGO_CGOCHECK=0):       no checks — silent corruption
//
// Run: go run ./03_cgo_use_after_free/
// Strict check: GOEXPERIMENT=cgocheck2 go run ./03_cgo_use_after_free/

package main

/*
#include <stdio.h>
#include <stdlib.h>

// Simulates a C library with a global cache that stores pointers for later.
static void* g_stored = NULL;

// DANGEROUS: stores a Go pointer beyond the CGo call boundary.
void store_go_ptr(void* p) {
    g_stored = p;
}

// Reads back the stored pointer — may be dangling if GC has run.
void use_stored_ptr(void) {
    if (g_stored == NULL) return;
    // Undefined behaviour if Go GC moved or freed the object.
    printf("[C] stored ptr value: \"%s\"\n", (char*)g_stored);
}

// Safe variant: uses the pointer only within this call, never stores it.
void echo_string(const char* s) {
    printf("[C] echo: \"%s\"\n", s);
}
*/
import "C"
import (
	"fmt"
	"runtime"
	"unsafe"
)

// ── ANTI-PATTERN ──────────────────────────────────────────────────────────────

// antipatternStoreGoPointerInC violates the CGo pointer rule by letting C
// store a Go pointer in a global. After the call returns, Go may GC the object.
//
// This code compiles and often runs without visible crash because the GC
// may not happen to move the object during the demo. That is the danger:
// the bug is non-deterministic and silent until it corrupts memory in production.
//
// With GOEXPERIMENT=cgocheck2 this panics immediately with:
//
//	"panic: cgo argument has Go pointer to unpinned Go pointer"
func antipatternStoreGoPointerInC() {
	data := make([]byte, 32)
	copy(data, "secret Go data\x00")

	fmt.Printf("ANTI-PATTERN | Go address before CGo call: %p\n", &data[0])

	// ILLEGAL: C stores &data[0] globally; data may be GC'd after this returns.
	C.store_go_ptr(unsafe.Pointer(&data[0]))

	// Drop the only Go reference — data is now eligible for collection.
	data = nil
	runtime.GC()
	runtime.GC()
	runtime.GC()

	fmt.Println("ANTI-PATTERN | After GC (data=nil), C reads the stored Go pointer:")
	fmt.Println("ANTI-PATTERN | ↳ use-after-free — may print garbage, may segfault")
	C.use_stored_ptr()
}

// ── SAFE ALTERNATIVES ─────────────────────────────────────────────────────────

// safePassStringToC copies the Go string into C-managed memory with C.CString.
// C heap memory is NOT tracked by the Go GC, so it is safe to store in C globals
// and read at any time — as long as you free it when done.
func safePassStringToC() {
	msg := "safe Go data"

	// C.CString calls malloc — the pointer lives on the C heap, outside GC.
	cStr := C.CString(msg)
	defer C.free(unsafe.Pointer(cStr)) // MUST free; Go GC will never do it

	fmt.Print("SAFE (CString)  | ")
	C.echo_string(cStr)
}

// safePinGoMemory uses runtime.Pinner (Go 1.21+) to tell the GC:
// "do not move this object while the pin is held."
// The original Go memory is used — no copy — but the address is guaranteed stable.
func safePinGoMemory() {
	data := []byte("pinned Go data\x00")

	var pinner runtime.Pinner
	pinner.Pin(&data[0]) // GC will not move data[0] until Unpin is called
	defer pinner.Unpin()

	// The address is stable for the lifetime of the pin.
	fmt.Print("SAFE (Pinner)   | ")
	C.echo_string((*C.char)(unsafe.Pointer(&data[0])))
}

func main() {
	fmt.Println("=== 03: Use-After-Free via CGo ===")
	fmt.Println()

	antipatternStoreGoPointerInC()
	fmt.Println()

	safePassStringToC()
	safePinGoMemory()
	fmt.Println()
	fmt.Println("TIP: Run with GOEXPERIMENT=cgocheck2 to make the anti-pattern panic immediately.")
}
