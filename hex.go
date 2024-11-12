package main

import (
	"fmt"
	"gohex/utils"
)

type HexInfo struct {
	Address             string
	HexRepresentation   string
	AsciiRepresentation string
}

func getHexRepresentation(file []byte, start int, end int) string {
	hexRepresentation := ""
	for j := start; j < end; j++ {
		hexRepresentation += fmt.Sprintf("%02X ", file[j])
	}

	return hexRepresentation
}

func getAsciiRepresentation(file []byte, start int, end int) string {
	asciiRepresentation := " |"
	for j := start; j < end; j++ {
		if file[j] >= 32 && file[j] <= 126 {
			asciiRepresentation += fmt.Sprintf("%c", file[j])
		} else {
			asciiRepresentation += "."
		}
	}
	asciiRepresentation += "|"

	return asciiRepresentation
}

func HexExtractor(filename string) ([]HexInfo, error) {
	file, err := utils.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var hexInfo []HexInfo

	fileLen := len(file)
	for i := 0; i < fileLen; i += 16 {
		end := i + 16
		if end > fileLen {
			end = fileLen
		}

		address := fmt.Sprintf("%04X ", i)

		hexRepresentation := getHexRepresentation(file, i, end)

		// Add extra spaces
		for j := end; j < i+16; j++ {
			hexRepresentation += "  "
		}

		asciiRepresentation := getAsciiRepresentation(file, i, end)

		hexInfo = append(hexInfo, HexInfo{
			Address:             address,
			HexRepresentation:   hexRepresentation,
			AsciiRepresentation: asciiRepresentation,
		})
	}

	return hexInfo, nil
}
