package main

import (
	"fmt"
	"os"

	"gohex/utils"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/urfave/cli/v2"
)

func main() {
	logger := utils.NewLogger()

	app := &cli.App{
		Name:  "GoHex",
		Usage: "Hex editor and disassembler",
		Commands: []*cli.Command{
			{
				Name:  "hex",
				Usage: "View the hexdump of a binary file",
				Action: func(c *cli.Context) error {
					hexInfoArr, err := HexExtractor(c.Args().Get(0))
					if err != nil {
						return fmt.Errorf("error extracting hex info: %v", err)
					}

					m := model{Render(hexInfoArr)}
					if _, err = tea.NewProgram(m).Run(); err != nil {
						return fmt.Errorf("error running program: %v", err)
					}

					return nil
				},
			},
			{
				Name:  "disassemble",
				Usage: "Disassemble a binary file",
				Action: func(c *cli.Context) error {
					err := Disassemble(c.Args().Get(0))
					if err != nil {
						return err
					}

					return nil
				},
			},
		},
		Action:  nil,
		Version: "0.1.0",
	}

	if err := app.Run(os.Args); err != nil {
		logger.Fatalln(err)
	}
}
