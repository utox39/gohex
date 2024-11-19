package main

/*
#cgo LDFLAGS: -lcapstone -lelf disassembler.o
#include <stdlib.h>
#include "disassembler/disassembler.h"
*/
import "C"

import "unsafe"

func Disassemble(filename string) string {
	cFilename := C.CString(filename)
	defer C.free(unsafe.Pointer(cFilename))

	var cOutput *C.char

	C.disassemble(cFilename, &cOutput)

	goOutput := C.GoString(cOutput)

	C.free(unsafe.Pointer(cOutput))

	return goOutput
}
