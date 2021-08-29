.PHONY: all
all: test

.PHONY: test
test:
	go test
	
.PHONY: test_coverage
test_coverage:
	go test `go list ./... | grep -v 'hack\|google'` -coverprofile=coverage.txt -covermode=atomic
