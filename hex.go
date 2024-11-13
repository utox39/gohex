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

const BytesPerLine int = 16

func getHexRepresentation(file []byte, start int, end int) string {
	hexRepresentation := ""
	for i := start; i < end; i++ {
		hexRepresentation += fmt.Sprintf("%02X ", file[i])
	}

	return hexRepresentation
}

func getAsciiRepresentation(file []byte, start int, end int) string {
	asciiRepresentation := " |"
	for i := start; i < end; i++ {
		if file[i] >= 32 && file[i] <= 126 {
			asciiRepresentation += fmt.Sprintf("%c", file[i])
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
	for i := 0; i < fileLen; i += BytesPerLine {
		end := i + BytesPerLine
		if end > fileLen {
			end = fileLen
		}

		address := fmt.Sprintf("%04X ", i)

		hexRepresentation := getHexRepresentation(file, i, end)

		asciiRepresentation := getAsciiRepresentation(file, i, end)

		hexInfo = append(hexInfo, HexInfo{
			Address:             address,
			HexRepresentation:   hexRepresentation,
			AsciiRepresentation: asciiRepresentation,
		})
	}

	return hexInfo, nil
}
