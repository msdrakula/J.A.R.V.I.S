.PHONY: build test clean install uninstall go-install lint fmt help

# Переменные
BINARY_NAME=jarvis
PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
SHAREDIR ?= $(PREFIX)/share/jarvis
VERSION=$(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME=$(shell date -u '+%Y-%m-%d_%H:%M:%S')
LDFLAGS=-ldflags "-X main.version=$(VERSION) -X main.buildTime=$(BUILD_TIME)"

# Цвета для вывода
COLOR_RESET=\033[0m
COLOR_GREEN=\033[32m
COLOR_YELLOW=\033[33m
COLOR_BLUE=\033[34m

help: ## Показать помощь
	@echo "$(COLOR_BLUE)JARVIS - Safe Internal Audit Tool$(COLOR_RESET)"
	@echo ""
	@echo "Доступные команды:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  $(COLOR_GREEN)%-15s$(COLOR_RESET) %s\n", $$1, $$2}'

build: ## Собрать бинарник
	@echo "$(COLOR_GREEN)Building $(BINARY_NAME)...$(COLOR_RESET)"
	go build $(LDFLAGS) -o $(BINARY_NAME) ./cmd/jarvis
	@echo "$(COLOR_GREEN)Built: ./$(BINARY_NAME)$(COLOR_RESET)"

test: ## Запустить тесты
	@echo "$(COLOR_GREEN)Running tests...$(COLOR_RESET)"
	go test -v ./...
	@echo "$(COLOR_GREEN)Tests passed$(COLOR_RESET)"

test-coverage: ## Запустить тесты с покрытием
	@echo "$(COLOR_GREEN)Running tests with coverage...$(COLOR_RESET)"
	go test -coverprofile=coverage.txt -covermode=atomic ./...
	go tool cover -html=coverage.txt -o coverage.html
	@echo "$(COLOR_GREEN)Coverage report: coverage.html$(COLOR_RESET)"

clean: ## Очистить артефакты сборки
	@echo "$(COLOR_YELLOW)Cleaning...$(COLOR_RESET)"
	rm -f $(BINARY_NAME) $(BINARY_NAME).exe
	rm -f coverage.txt coverage.html
	rm -rf results/
	@echo "$(COLOR_GREEN)Cleaned$(COLOR_RESET)"

install: build ## Установить jarvis глобально в /usr/local/bin (нужен sudo)
	@echo "$(COLOR_GREEN)Installing $(BINARY_NAME) to $(BINDIR)...$(COLOR_RESET)"
	install -d $(DESTDIR)$(BINDIR)
	install -m 755 $(BINARY_NAME) $(DESTDIR)$(BINDIR)/$(BINARY_NAME)
	install -d $(DESTDIR)$(SHAREDIR)/wordlists
	-install -m 644 rules.yaml waf_signatures.yaml $(DESTDIR)$(SHAREDIR)/
	-install -m 644 wordlists/* $(DESTDIR)$(SHAREDIR)/wordlists/
	@echo "$(COLOR_GREEN)Installed: $(BINDIR)/$(BINARY_NAME)$(COLOR_RESET)"
	@echo "From any directory: jarvis scan -u https://example.com -o ./results"

uninstall: ## Удалить глобальную установку из /usr/local
	rm -f $(DESTDIR)$(BINDIR)/$(BINARY_NAME)
	rm -rf $(DESTDIR)$(SHAREDIR)
	@echo "$(COLOR_YELLOW)Removed $(BINDIR)/$(BINARY_NAME)$(COLOR_RESET)"

go-install: ## Установить в GOPATH/bin (без sudo, если GOPATH/bin в PATH)
	@echo "$(COLOR_GREEN)Installing $(BINARY_NAME) via go install...$(COLOR_RESET)"
	go install $(LDFLAGS) ./cmd/jarvis
	@echo "$(COLOR_GREEN)Installed to $(shell go env GOPATH)/bin/$(BINARY_NAME)$(COLOR_RESET)"

lint: ## Запустить линтер
	@echo "$(COLOR_GREEN)Running linter...$(COLOR_RESET)"
	@if command -v golangci-lint > /dev/null; then \
		golangci-lint run; \
	else \
		echo "golangci-lint not installed. Install: https://golangci-lint.run/usage/install/"; \
	fi

fmt: ## Форматировать код
	@echo "$(COLOR_GREEN)Formatting code...$(COLOR_RESET)"
	gofmt -w -s .
	@echo "$(COLOR_GREEN)Formatted$(COLOR_RESET)"

build-all: ## Собрать бинарники для всех платформ
	@echo "$(COLOR_GREEN)Building for all platforms...$(COLOR_RESET)"
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o $(BINARY_NAME)-linux-amd64 ./cmd/jarvis
	GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o $(BINARY_NAME)-linux-arm64 ./cmd/jarvis
	GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o $(BINARY_NAME)-darwin-amd64 ./cmd/jarvis
	GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o $(BINARY_NAME)-darwin-arm64 ./cmd/jarvis
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o $(BINARY_NAME)-windows-amd64.exe ./cmd/jarvis
	@echo "$(COLOR_GREEN)Built binaries for Linux, macOS, Windows$(COLOR_RESET)"

run: build ## Собрать и показать справку (config.yaml не нужен)
	@echo "$(COLOR_BLUE)Running $(BINARY_NAME)...$(COLOR_RESET)"
	./$(BINARY_NAME) scan --help

docker-build: ## Собрать Docker-образ
	@echo "$(COLOR_GREEN)Building Docker image...$(COLOR_RESET)"
	docker build -t $(BINARY_NAME):$(VERSION) .
	@echo "$(COLOR_GREEN)Built: $(BINARY_NAME):$(VERSION)$(COLOR_RESET)"

docker-run: ## Запустить в Docker-контейнере
	@echo "$(COLOR_BLUE)Running in Docker...$(COLOR_RESET)"
	docker run --rm -v $(PWD)/results:/results $(BINARY_NAME):$(VERSION) scan -u https://example.com -o /results
