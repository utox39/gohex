LIBCAPSTONENAME = capstone
LIBELFNAME = elf

build: clean build-disassembler
	go build -ldflags "-w -s" -o gohex main.go tui.go hex.go disassembler.go
	rm *.o

build-disassembler:
	${CC} -c ./disassembler/disassembler.c -l$(LIBCAPSTONENAME) -l$(LIBELFNAME)

clean:
	rm -rf ./gohex *.o
