package utils

import (
	"log"
	"os"
)

func NewLogger() *log.Logger {
	return log.New(os.Stderr, os.Args[0]+": ", 0)
}
