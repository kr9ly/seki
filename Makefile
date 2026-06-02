.PHONY: build install clean

build:
	go build -o seki ./cmd/seki

install:
	rm -f ~/.local/bin/seki
	go build -o ~/.local/bin/seki ./cmd/seki

clean:
	rm -f seki
