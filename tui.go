package main

import (
	"strings"

	"github.com/charmbracelet/bubbles/table"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

var baseStyle = lipgloss.NewStyle().
	BorderStyle(lipgloss.NormalBorder()).
	BorderForeground(lipgloss.Color("240"))

type model struct {
	table table.Model
}

func (m model) Init() tea.Cmd { return nil }

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c", "esc":
			return m, tea.Quit

		case "shift+up":
			m.table.MoveUp(10)

		case "shift+down":
			m.table.MoveDown(10)

		case "alt+up":
			m.table.MoveUp(100)

		case "alt+down":
			m.table.MoveDown(100)

		case "shift+left":
			m.table.MoveUp(1000)

		case "shift+right":
			m.table.MoveDown(1000)
		}
	}
	m.table, cmd = m.table.Update(msg)
	return m, cmd
}

func (m model) View() string {
	body := strings.Builder{}

	body.WriteString("GoHex\n- shift+up/down: scroll 10 lines, ")
	body.WriteString("alt+up/down: scroll 100 lines\n")
	body.WriteString("- shift+left/right: scroll 1000 lines\n\n")

	body.WriteString(m.table.View())

	return baseStyle.Render(body.String()) + "\n"
}

func Render(hexInfo []HexInfo) table.Model {
	columns := []table.Column{
		{Title: "Address", Width: 10},
		{Title: "00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F", Width: 50},
		{Title: "ASCII", Width: 20},
	}

	var rows []table.Row
	var row table.Row
	for _, h := range hexInfo {
		row = table.Row{h.Address, h.HexRepresentation, h.AsciiRepresentation}
		rows = append(rows, row)
	}

	t := table.New(
		table.WithColumns(columns),
		table.WithRows(rows),
		table.WithFocused(true),
		table.WithHeight(30),
	)

	s := table.DefaultStyles()
	s.Header = s.Header.
		BorderStyle(lipgloss.NormalBorder()).
		BorderForeground(lipgloss.Color("240")).
		BorderBottom(true).
		Bold(false)
	s.Selected = s.Selected.
		Foreground(lipgloss.Color("229")).
		Background(lipgloss.Color("57")).
		Bold(false)

	t.SetStyles(s)

	return t
}
