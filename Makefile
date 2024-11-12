build:
	go build -ldflags "-w -s" -o gohex main.go tui.go hex.go

clean:
	rm ./gohex
