package utils

import (
	"fmt"
	"os"
)

func ReadFile(path string) ([]byte, error) {
	file, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("error opening the file: %v\n", err)
	}
	return file, nil
}
