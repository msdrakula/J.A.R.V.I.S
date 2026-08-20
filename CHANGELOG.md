# Changelog

Все значимые изменения в проекте будут документироваться в этом файле.

Формат основан на [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
и этот проект придерживается [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.1.0] - 2026-08-20

### Added
- `jarvis scan -u` работает без `config.yaml` (дефолты: level 3, стандартные wordlists)
- `make install` копирует бинарник в `/usr/local/bin`

### Changed
- README: одна рабочая последовательность для Kali (`go build` + `sudo install`), без `go install @latest` (тег v1.0.0 не содержит `cmd/jarvis`)
- Лицензия MIT, исходники `cmd/jarvis` в репозитории

## [1.0.0] - 2026-08-19

### Added
- Модульная архитектура с разделением на cli, config, httpclient, storage, modules, report
- CLI на Cobra с командами: scan, recon, portscan, dirbust, history, show, report, query, diff, resume
- Конфигурация через Viper (YAML-файлы + флаги CLI)
- Логирование через Zap с уровнями debug, info, warn, error
- SQLite-хранилище через modernc.org/sqlite (чистый Go, без CGO)
- HTTP-клиент с retry, rate-limit, прокси, gzip, ротацией User-Agent
- Модуль `recon`: DNS-резолвинг, TLS-сертификаты, robots.txt, sitemap.xml, извлечение параметров из HTML
- Модуль `availability`: проверка доступности TCP-портов, определение сервисов по баннерам
- Модуль `urlaudit`: проверка путей по словарю, фильтрация soft 404, анализ security headers
- Модуль `compliance`: YAML-шаблоны с матчерами (status, header, word, regex)
- Модуль `waflib`: пассивное обнаружение WAF/CDN по сигнатурам (Cloudflare, AWS WAF, Imperva, Akamai)
- Модуль `resilience`: проверка устойчивости ввода с безопасными маркерными строками
- 5 уровней детальности (stealth, polite, normal, aggressive, thorough)
- Graceful shutdown с сохранением прогресса (статус `paused`)
- HTML-дашборд с группировкой по severity и цветовой кодировкой
- Экспорт в форматы: JSON, Markdown, HTML, CSV, Nmap XML
- Команда `diff` для сравнения двух сканов (терминал и HTML)
- Визуализация дерева путей в терминале с ANSI-цветами
- Команда `resume` для возобновления прерванных сканов
- Юнит-тесты для ключевых функций
- GitHub Actions для автоматической сборки и тестирования
- Deb-пакет для Debian/Kali Linux
