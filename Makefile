build:
	go build -o gohex main.go tui.go hex.go

clean:
	rm ./gohex