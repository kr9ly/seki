.PHONY: build install clean

build:
	go build -o seki ./cmd/seki

install:
	rm -f "$$(go env GOPATH)/bin/seki"
	go build -o "$$(go env GOPATH)/bin/seki" ./cmd/seki

clean:
	rm -f seki
