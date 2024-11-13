package main

import (
	"gohex/utils"
	"os"

	tea "github.com/charmbracelet/bubbletea"
)

func main() {
	logger := utils.NewLogger()

	hexInfoArr, err := HexExtractor(os.Args[1])
	if err != nil {
		logger.Fatalln(err)
	}

	m := model{Render(hexInfoArr)}
	if _, err = tea.NewProgram(m).Run(); err != nil {
		logger.Fatalln("Error running program:", err)
	}
}
