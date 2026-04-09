.PHONY: build install clean

build:
	go build -o seki ./cmd/seki

install:
	go install ./cmd/seki

clean:
	rm -f seki
