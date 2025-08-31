# Makefile для CASB Security System

.PHONY: help install install-dev test test-cov lint format clean run docker-build docker-run backup

# Переменные
PYTHON := python3
PIP := pip
VENV := venv
SOURCE_DIR := .
TEST_DIR := tests

# Цвета для вывода
BLUE := \033[0;34m
GREEN := \033[0;32m
YELLOW := \033[1;33m
RED := \033[0;31m
NC := \033[0m # No Color

help: ## Показать справку по командам
	@echo "$(BLUE)CASB Security System - Makefile команды$(NC)"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "$(GREEN)%-20s$(NC) %s\n", $$1, $$2}'

install: ## Установка production зависимостей
	@echo "$(BLUE)Установка production зависимостей...$(NC)"
	$(PYTHON) -m venv $(VENV)
	./$(VENV)/bin/pip install --upgrade pip
	./$(VENV)/bin/pip install -r requirements.txt
	@echo "$(GREEN)Зависимости установлены$(NC)"

install-dev: ## Установка всех зависимостей включая dev
	@echo "$(BLUE)Установка dev зависимостей...$(NC)"
	$(PYTHON) -m venv $(VENV)
	./$(VENV)/bin/pip install --upgrade pip
	./$(VENV)/bin/pip install -r requirements.txt
	./$(VENV)/bin/pip install -r requirements-dev.txt
	@echo "$(GREEN)Dev зависимости установлены$(NC)"

test: ## Запуск тестов
	@echo "$(BLUE)Запуск тестов...$(NC)"
	./$(VENV)/bin/pytest $(TEST_DIR) -v

test-cov: ## Запуск тестов с покрытием кода
	@echo "$(BLUE)Запуск тестов с покрытием...$(NC)"
	./$(VENV)/bin/pytest $(TEST_DIR) --cov=$(SOURCE_DIR) --cov-report=html --cov-report=term

lint: ## Проверка качества кода
	@echo "$(BLUE)Проверка качества кода...$(NC)"
	./$(VENV)/bin/flake8 $(SOURCE_DIR) --max-line-length=100 --ignore=E203,W503
	./$(VENV)/bin/mypy $(SOURCE_DIR) --ignore-missing-imports
	./$(VENV)/bin/bandit -r $(SOURCE_DIR) -x tests/ -f json -o bandit-report.json || true
	@echo "$(GREEN)Проверка завершена$(NC)"

format: ## Форматирование кода
	@echo "$(BLUE)Форматирование кода...$(NC)"
	./$(VENV)/bin/black $(SOURCE_DIR)
	./$(VENV)/bin/isort $(SOURCE_DIR)
	@echo "$(GREEN)Код отформатирован$(NC)"

security-check: ## Проверка безопасности
	@echo "$(BLUE)Проверка безопасности...$(NC)"
	./$(VENV)/bin/safety check
	./$(VENV)/bin/bandit -r $(SOURCE_DIR) -x tests/
	@echo "$(GREEN)Проверка безопасности завершена$(NC)"

clean: ## Очистка временных файлов
	@echo "$(BLUE)Очистка временных файлов...$(NC)"
	find . -type f -name "*.pyc" -delete
	find . -type d -name "__pycache__" -delete
	find . -type f -name "*.log" -delete
	rm -rf .pytest_cache/
	rm -rf .coverage
	rm -rf htmlcov/
	rm -rf .mypy_cache/
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info/
	@echo "$(GREEN)Очистка завершена$(NC)"

run: ## Запуск CASB системы в режиме разработки
	@echo "$(BLUE)Запуск CASB системы...$(NC)"
	./$(VENV)/bin/python app.py

run-prod: ## Запуск в production режиме с Gunicorn
	@echo "$(BLUE)Запуск в production режиме...$(NC)"
	./$(VENV)/bin/gunicorn -c gunicorn.conf.py app:app

setup-dev: install-dev ## Настройка среды разработки
	@echo "$(BLUE)Настройка среды разработки...$(NC)"
	cp config.yaml.example config.yaml
	mkdir -p data logs ssl
	./$(VENV)/bin/pre-commit install
	@echo "$(GREEN)Среда разработки настроена$(NC)"
	@echo "$(YELLOW)Не забудьте отредактировать config.yaml$(NC)"

docker-build: ## Сборка Docker образа
	@echo "$(BLUE)Сборка Docker образа...$(NC)"
	docker build -t casb-security:latest .
	@echo "$(GREEN)Docker образ собран$(NC)"

docker-run: ## Запуск Docker контейнера
	@echo "$(BLUE)Запуск Docker контейнера...$(NC)"
	docker-compose up -d
	@echo "$(GREEN)Docker контейнер запущен$(NC)"

docker-stop: ## Остановка Docker контейнера
	@echo "$(BLUE)Остановка Docker контейнера...$(NC)"
	docker-compose down
	@echo "$(GREEN)Docker контейнер остановлен$(NC)"

docker-logs: ## Просмотр логов Docker
	docker-compose logs -f casb-app

backup: ## Создание резервной копии
	@echo "$(BLUE)Создание резервной копии...$(NC)"
	./scripts/backup.sh
	@echo "$(GREEN)Резервная копия создана$(NC)"

init-db: ## Инициализация базы данных
	@echo "$(BLUE)Инициализация базы данных...$(NC)"
	mkdir -p data
	./$(VENV)/bin/python -c "from core.casb import CASBCore; CASBCore('data/casb.db')"
	@echo "$(GREEN)База данных инициализирована$(NC)"

migrate: ## Миграция базы данных
	@echo "$(BLUE)Миграция базы данных...$(NC)"
	# Здесь будут команды миграции когда они понадобятся
	@echo "$(GREEN)Миграция завершена$(NC)"

docs: ## Генерация документации
	@echo "$(BLUE)Генерация документации...$(NC)"
	./$(VENV)/bin/sphinx-build -b html docs/ docs/_build/
	@echo "$(GREEN)Документация сгенерирована в docs/_build/$(NC)"

pre-commit: format lint test ## Проверки перед коммитом
	@echo "$(GREEN)Все проверки прошли успешно$(NC)"

install-system: ## Системная установка (требует sudo)
	@echo "$(BLUE)Системная установка CASB...$(NC)"
	sudo ./scripts/install.sh install
	@echo "$(GREEN)Системная установка завершена$(NC)"

uninstall-system: ## Удаление системной установки (требует sudo)
	@echo "$(RED)Удаление системной установки CASB...$(NC)"
	sudo ./scripts/install.sh uninstall

check-deps: ## Проверка зависимостей
	@echo "$(BLUE)Проверка зависимостей...$(NC)"
	./$(VENV)/bin/pip check
	./$(VENV)/bin/safety check
	@echo "$(GREEN)Зависимости в порядке$(NC)"

benchmark: ## Запуск бенчмарков производительности
	@echo "$(BLUE)Запуск бенчмарков...$(NC)"
	./$(VENV)/bin/python scripts/benchmark.py
	@echo "$(GREEN)Бенчмарки завершены$(NC)"

load-test: ## Нагрузочное тестирование
	@echo "$(BLUE)Нагрузочное тестирование...$(NC)"
	./$(VENV)/bin/locust -f tests/load_test.py --headless -u 10 -r 2 -t 60s
	@echo "$(GREEN)Нагрузочное тестирование завершено$(NC)"

release: ## Подготовка к релизу
	@echo "$(BLUE)Подготовка к релизу...$(NC)"
	$(MAKE) clean
	$(MAKE) format
	$(MAKE) lint
	$(MAKE) test-cov
	$(MAKE) security-check
	@echo "$(GREEN)Готов к релизу$(NC)"

# Алиасы
build: docker-build
up: docker-run
down: docker-stop
logs: docker-logs
dev: setup-dev run
