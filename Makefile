.PHONY: fmt-check vet test vulncheck fuzz

fmt-check:
	@files="$$(gofmt -l .)" && test -z "$$files" || { printf '%s\n' "$$files"; exit 1; }

vet:
	go vet ./...

test:
	go test -race -count=1 ./...

vulncheck:
	go run golang.org/x/vuln/cmd/govulncheck@latest ./...

fuzz:
	go test -run '^$$' -fuzz FuzzSafeRedirect -fuzztime 60s .
