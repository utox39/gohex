package main

/*
#cgo LDFLAGS: -L./build -lgohexdisassembler -lcapstone -lLIEF

#include <stdlib.h>
#include  "disassembler/disassembler_wrapper.h"
*/
import "C"

import (
	"fmt"
	"unsafe"
)

func Disassemble(filename string) error {
	cFilename := C.CString(filename)
	defer C.free(unsafe.Pointer(cFilename))

	exitStatus := C.disassembler_wrapper(cFilename)

	if exitStatus != 0 {
		return fmt.Errorf("disassembler error")
	}

	return nil
}
