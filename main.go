package main

import (
	"log"
	"os"

	tea "github.com/charmbracelet/bubbletea"
)

func main() {
	hexInfoArr, err := HexExtractor(os.Args[1])
	if err != nil {
		log.Fatalln(err)
	}

	m := model{Render(hexInfoArr)}
	if _, err = tea.NewProgram(m).Run(); err != nil {
		log.Fatalln("Error running program:", err)
	}
}
