package utils

import (
	"fmt"
	"os"
)

func ReadFile(path string) ([]byte, error) {
	file, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("error opening the file: %s: %v\n", os.Args[1], err)
	}
	return file, nil
}
