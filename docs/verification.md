# Результат первой итерации — 24.10.2026

Программная часть этапов 0–1 реализована. Сетевой acceptance не завершён; этапы имеют статус Partial согласно milestones.md. Реальные системные маршруты в этой сессии не изменялись.

## Полученные результаты

| Проверка | Результат |
|---|---|
| `dotnet restore PathFlux.slnx --locked-mode --force --disable-parallel` | Успех, в том числе после publish; NuGet audit без предупреждений |
| Release build всего решения | Успех, 0 ошибок / 0 предупреждений |
| Policy.Tests | 53 passed |
| Infrastructure.Tests | 48 passed |
| Engine.Tests с PATHFLUX_TEST_ENGINE | 11 passed, включая официальный sing-box check для SOCKS5, HTTP и HTTPS CONNECT, credentials, Block и служебного DNS |
| App.Tests | 6 passed |
| Все тесты | **118 passed, 0 failed, 0 skipped** в финальном прогоне |
| Native UI smoke | Exit 0; все шесть вкладок, обе темы, 12 PNG |
| Published UI smoke | Exit 0 из artifacts/win-x64 |
| Агент без параметров | Exit 2, запрос отклонён без UAC и TUN |
| `scripts/publish.ps1` | Portable Windows x64 framework-dependent приложение и agent/ собраны |
| Облачный GitHub Actions | Workflow подготовлен; удалённый запуск не выполнялся |

Финальная команда тестов (Windows PowerShell, из корня):

```powershell
$env:PATHFLUX_TEST_ENGINE = Join-Path (Get-Location) '.local/engine/unpacked/sing-box-1.12.12-windows-amd64/sing-box.exe'
dotnet test PathFlux.slnx -c Release --no-restore --nologo -m:1 -nr:false -p:UseSharedCompilation=false --logger trx --results-directory TestResults
```

Путь в примере соответствует локальному кэшу проверки. При обычной установке использовать EnginePath, возвращённый scripts/get-engine.ps1. Без переменной среды единственный внешний engine-test помечается Skipped; это не подтверждение проверки бинарника. TRX находятся в игнорируемом TestResults/. Запуск VSTest в sandbox зависал на старте; финальные прогоны выполнены вне sandbox. Скачанный официальный архив и EXE сверены с закреплёнными SHA-256, бинарники не добавлены в Git.

## Объём изменений

- Корень: global.json, Directory.Build.props/targets, PathFlux.slnx, README, LICENSE, .gitignore; lock-файлы проектов; .github/workflows/build.yml.
- Существующий PathFlux/: App, Program, MainWindow, MainWindowViewModel; Resources/ru.json и en.json. Шесть реальных вкладок вместо стартовой надписи.
- src/PathFlux.Domain/: Models.cs; профили, правила, capabilities, состояния и идентификатор экземпляра процесса.
- src/PathFlux.Application/: Contracts.cs, ConfigurationValidator.cs, RuleCompiler.cs, ISecretReferenceRetention.cs.
- src/PathFlux.Infrastructure/: JsonConfigurationStore.cs, DpapiSecretStore.cs, ProcessDiscoveryService.cs, ProxyDiagnostics.cs.
- src/PathFlux.Engine/: SingBoxConfigGenerator.cs, EngineBinary.cs, AgentProtocol.cs, SingBoxEngineAdapter.cs.
- src/PathFlux.Agent/: Program.cs и EngineSession.cs; UAC-граница, подтверждение peer PID, Job Object, timeout и recovery journal.
- tests/: Policy / Infrastructure / Engine / App — четыре тестовых проекта.
- scripts/: get-engine.ps1 и publish.ps1; examples/config.json без паролей; docs/: архитектура, ADR, безопасность, сеть, ограничения, этапы и эта проверка. docs/images/overview.png — окно с демонстрационными данными smoke-режима.

## Открытая приёмка

Не проверены реальный TUN, процессная атрибуция Windows, два одинаковых имени EXE по разным путям, несколько upstream, внешние TCP выходы, DNS/IPv6, аварийный recovery, VPN/Docker, sleep/wake и Windows reboot. Наличие кода запуска агента и check не означает успешный прогон этих сценариев.

UDP payload/relay и Discord voice не проверялись; Proxy UDP остаётся заблокированным. UDP ASSOCIATE диагностика различает Unsupported upstream, Failed и NotVerified. Точный PID, потомки, Direct fallback при сбое, kill switch и дополнительные протоколы не реализованы. HTTPS диагностика проверяет TLS самого HTTPS-прокси, а не TLS целевого HTTPS-сайта внутри туннеля. Статистика сетевых соединений и полноценное структурированное журналирование движка пока отсутствуют: UI содержит ограниченный безопасный журнал сессии, сырой stdout/stderr скрыт.

Следующий минимальный шаг — выполнить network-design.md на тестовой Windows с подконтрольным upstream и записать результаты selective TCP и остановки/аварии TUN. Только после этого завершать приёмку этапа 1 и переходить к UDP echo этапа 2.
