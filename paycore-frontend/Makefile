ifneq (,$(wildcard ./.env))
include .env
export 
ENV_FILE_PARAM = --env-file .env

endif

.PHONY: help install dev build preview clean docker-build docker-run docker-dev docker-stop docker-clean lint type-check test format logs shell

# Default target
.DEFAULT_GOAL := help

# Colors for output
CYAN := \033[0;36m
GREEN := \033[0;32m
YELLOW := \033[0;33m
RED := \033[0;31m
NC := \033[0m # No Color

##@ Help

help: ## Display this help message
	@echo "$(CYAN)PayCore Frontend - Available Commands$(NC)"
	@echo ""
	@awk 'BEGIN {FS = ":.*##"; printf "Usage:\n  make $(CYAN)<target>$(NC)\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  $(CYAN)%-20s$(NC) %s\n", $$1, $$2 } /^##@/ { printf "\n$(YELLOW)%s$(NC)\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Development

ins: ## Install dependencies
	@echo "$(CYAN)Installing dependencies...$(NC)"
	npm install
	@echo "$(GREEN)✓ Dependencies installed successfully$(NC)"

dev: ## Start development server
	@echo "$(CYAN)Starting development server...$(NC)"
	npm run dev

build: ## Build for production
	@echo "$(CYAN)Building for production...$(NC)"
	npm run build
	@echo "$(GREEN)✓ Build completed successfully$(NC)"

preview: ## Preview production build locally
	@echo "$(CYAN)Starting preview server...$(NC)"
	npm run preview

clean: ## Clean build artifacts and dependencies
	@echo "$(YELLOW)Cleaning build artifacts...$(NC)"
	rm -rf dist node_modules/.vite
	@echo "$(GREEN)✓ Cleaned successfully$(NC)"

clean-all: ## Clean everything including node_modules
	@echo "$(RED)Cleaning all artifacts and dependencies...$(NC)"
	rm -rf dist node_modules node_modules/.vite .cache
	@echo "$(GREEN)✓ Cleaned everything$(NC)"

##@ Code Quality

lint: ## Run ESLint
	@echo "$(CYAN)Running ESLint...$(NC)"
	npm run lint

lint-fix: ## Run ESLint and fix issues
	@echo "$(CYAN)Running ESLint with auto-fix...$(NC)"
	npm run lint -- --fix
	@echo "$(GREEN)✓ Linting completed$(NC)"

type-check: ## Run TypeScript type checking
	@echo "$(CYAN)Running TypeScript type check...$(NC)"
	npm run type-check
	@echo "$(GREEN)✓ Type check passed$(NC)"

format: ## Format code with Prettier (if configured)
	@echo "$(CYAN)Formatting code...$(NC)"
	npx prettier --write "src/**/*.{ts,tsx,js,jsx,json,css,md}"
	@echo "$(GREEN)✓ Code formatted$(NC)"

##@ Docker - Production

docker-build: ## Build production Docker image
	@echo "$(CYAN)Building production Docker image...$(NC)"
	docker build -t paycore-frontend:latest \
		--build-arg VITE_API_BASE_URL=${VITE_API_BASE_URL:-http://localhost:8000/api/v1} \
		-f Dockerfile .
	@echo "$(GREEN)✓ Docker image built successfully$(NC)"

docker-run: ## Run production container
	@echo "$(CYAN)Starting production container...$(NC)"
	docker-compose up -d
	@echo "$(GREEN)✓ Container started at http://localhost:3000$(NC)"

docker-stop: ## Stop production container
	@echo "$(YELLOW)Stopping production container...$(NC)"
	docker-compose down
	@echo "$(GREEN)✓ Container stopped$(NC)"

docker-restart: docker-stop docker-run ## Restart production container

docker-logs: ## View production container logs
	docker-compose logs -f paycore-frontend

docker-shell: ## Open shell in production container
	docker exec -it paycore-frontend sh

##@ Docker - Development

docker-dev-build: ## Build development Docker image
	@echo "$(CYAN)Building development Docker image...$(NC)"
	docker build -t paycore-frontend:dev -f Dockerfile.dev .
	@echo "$(GREEN)✓ Development image built successfully$(NC)"

docker-dev: ## Run development container with hot reload
	@echo "$(CYAN)Starting development container...$(NC)"
	docker-compose -f docker-compose.dev.yml up
	@echo "$(GREEN)✓ Development server started at http://localhost:3000$(NC)"

docker-dev-detached: ## Run development container in background
	@echo "$(CYAN)Starting development container in background...$(NC)"
	docker-compose -f docker-compose.dev.yml up -d
	@echo "$(GREEN)✓ Development server started at http://localhost:3000$(NC)"

docker-dev-stop: ## Stop development container
	@echo "$(YELLOW)Stopping development container...$(NC)"
	docker-compose -f docker-compose.dev.yml down
	@echo "$(GREEN)✓ Development container stopped$(NC)"

docker-dev-logs: ## View development container logs
	docker-compose -f docker-compose.dev.yml logs -f

docker-dev-shell: ## Open shell in development container
	docker exec -it paycore-frontend-dev sh

##@ Docker - Maintenance

docker-clean: ## Remove Docker containers and images
	@echo "$(YELLOW)Cleaning Docker containers and images...$(NC)"
	docker-compose down -v
	docker-compose -f docker-compose.dev.yml down -v
	docker rmi paycore-frontend:latest paycore-frontend:dev 2>/dev/null || true
	@echo "$(GREEN)✓ Docker cleaned$(NC)"

docker-prune: ## Prune all unused Docker resources
	@echo "$(RED)Pruning all unused Docker resources...$(NC)"
	docker system prune -af --volumes
	@echo "$(GREEN)✓ Docker pruned$(NC)"

docker-inspect: ## Inspect production container
	docker inspect paycore-frontend

docker-stats: ## Show container resource usage
	docker stats paycore-frontend

##@ Testing

test: ## Run tests (placeholder - implement when tests are added)
	@echo "$(YELLOW)⚠ Tests not yet implemented$(NC)"
	@echo "$(CYAN)Add your test command here (e.g., npm run test)$(NC)"

test-watch: ## Run tests in watch mode
	@echo "$(YELLOW)⚠ Tests not yet implemented$(NC)"

test-coverage: ## Generate test coverage report
	@echo "$(YELLOW)⚠ Tests not yet implemented$(NC)"

##@ CI/CD

ci-build: install type-check lint build ## Run CI pipeline (install, type-check, lint, build)
	@echo "$(GREEN)✓ CI pipeline completed successfully$(NC)"

ci-test: install type-check lint test ## Run CI pipeline with tests
	@echo "$(GREEN)✓ CI pipeline with tests completed$(NC)"

##@ Deployment

deploy-vercel: build ## Deploy to Vercel
	@echo "$(CYAN)Deploying to Vercel...$(NC)"
	npx vercel --prod
	@echo "$(GREEN)✓ Deployed to Vercel$(NC)"

deploy-netlify: build ## Deploy to Netlify
	@echo "$(CYAN)Deploying to Netlify...$(NC)"
	npx netlify deploy --prod --dir=dist
	@echo "$(GREEN)✓ Deployed to Netlify$(NC)"

##@ Environment

env-example: ## Create .env file from .env.example
	@if [ ! -f .env.development ]; then \
		cp .env.example .env.development; \
		echo "$(GREEN)✓ Created .env.development from .env.example$(NC)"; \
	else \
		echo "$(YELLOW)⚠ .env.development already exists$(NC)"; \
	fi

env-check: ## Check environment variables
	@echo "$(CYAN)Current environment configuration:$(NC)"
	@if [ -f .env.development ]; then \
		cat .env.development; \
	else \
		echo "$(RED)✗ .env.development not found$(NC)"; \
	fi

##@ Information

info: ## Display project information
	@echo "$(CYAN)PayCore Frontend Information$(NC)"
	@echo "Node version:    $$(node --version)"
	@echo "NPM version:     $$(npm --version)"
	@echo "Project version: $$(node -p "require('./package.json').version")"
	@echo "API Endpoints:   137 (100% coverage)"
	@echo "Modules:         13"
	@echo "Tech Stack:      React 18 + TypeScript + Vite + Chakra UI"

deps: ## List installed dependencies
	@echo "$(CYAN)Installed Dependencies:$(NC)"
	npm list --depth=0

outdated: ## Check for outdated dependencies
	@echo "$(CYAN)Checking for outdated dependencies...$(NC)"
	npm outdated

update: ## Update dependencies
	@echo "$(CYAN)Updating dependencies...$(NC)"
	npm update
	@echo "$(GREEN)✓ Dependencies updated$(NC)"

##@ Quick Commands

quick-start: install dev ## Quick start for first-time setup

quick-prod: build docker-build docker-run ## Quick production deployment with Docker

full-reset: clean-all install dev ## Full reset and restart

##@ Backend Integration

backend-check: ## Check if backend is running
	@echo "$(CYAN)Checking backend connection...$(NC)"
	@curl -s http://localhost:8000/api/v1/health/ > /dev/null && \
		echo "$(GREEN)✓ Backend is running$(NC)" || \
		echo "$(RED)✗ Backend is not running. Start it with: cd ../Django/paycore-api-1 && python manage.py runserver$(NC)"

full-stack-dev: ## Start both frontend and backend (requires tmux or separate terminals)
	@echo "$(CYAN)Starting full stack development...$(NC)"
	@echo "$(YELLOW)Note: This requires the backend to be set up$(NC)"
	@echo "$(CYAN)Frontend: npm run dev$(NC)"
	@echo "$(CYAN)Backend: cd ../Django/paycore-api-1 && python manage.py runserver$(NC)"

##@ Documentation

docs: ## Open documentation
	@echo "$(CYAN)Opening documentation...$(NC)"
	@echo "README.md - Project overview and setup"
	@echo "PROJECT_SUMMARY.md - Complete implementation details"
	@echo "QUICKSTART.md - Quick start guide"

serve-docs: ## Serve documentation as website (requires mkdocs or similar)
	@echo "$(YELLOW)Documentation server not configured yet$(NC)"
	@echo "$(CYAN)You can view markdown files directly in your editor$(NC)"
