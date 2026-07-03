.PHONY: build install release clean

DIST := dist

build:
	go build -o seki ./cmd/seki

install:
	rm -f ~/.local/bin/seki
	go build -o ~/.local/bin/seki ./cmd/seki

# Cross-compile release binaries. CGO-free (sqlite is modernc pure-Go),
# so this works from any host without a cross toolchain.
release:
	rm -rf $(DIST) && mkdir -p $(DIST)
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags "-s -w" -o $(DIST)/seki-linux-arm64 ./cmd/seki
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o $(DIST)/seki-linux-amd64 ./cmd/seki
	cd $(DIST) && sha256sum seki-linux-arm64 seki-linux-amd64 > SHA256SUMS

clean:
	rm -f seki
	rm -rf $(DIST)
