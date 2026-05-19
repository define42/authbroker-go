.PHONY: all test lint race govulncheck image validate-k8s verify

all:
	docker compose up --build
test:
	go test ./... -coverpkg=./... -cover

lint:
	go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.12.2 run

race:
	go test -race ./...

govulncheck:
	go run golang.org/x/vuln/cmd/govulncheck@latest ./...

image:
	docker build -t authbroker-go:verify .

validate-k8s:
	@if command -v kubeconform >/dev/null 2>&1; then \
		kubeconform -strict -summary deploy/kubernetes/*.yaml; \
	elif command -v kubectl >/dev/null 2>&1; then \
		kubectl apply --dry-run=client --validate=false -f deploy/kubernetes; \
	elif command -v docker >/dev/null 2>&1; then \
		docker run --rm -v "$$(pwd):/work" ghcr.io/yannh/kubeconform:latest -strict -summary /work/deploy/kubernetes; \
	else \
		echo "install kubeconform, kubectl, or docker to validate Kubernetes manifests" >&2; \
		exit 1; \
	fi

verify: lint test race govulncheck image validate-k8s
