# Разработка и проверка

Цель: Windows 10/11 x64. global.json закрепляет установленный .NET SDK 10.0.401. Решение сохраняет исходный Avalonia-проект, добавлены Domain, Application, Infrastructure, Engine, Agent и четыре проекта тестов. Зависимости и решения: adr-001-engine.md. Файлы packages.lock.json фиксируют транзитивные версии; RuntimeIdentifiers=win-x64 сохраняет совместимость обычного restore и publish.

```powershell
dotnet restore PathFlux.slnx --locked-mode
dotnet build PathFlux.slnx -c Release --no-restore
dotnet test PathFlux.slnx -c Release --no-build
dotnet run --project PathFlux/PathFlux.csproj -c Release --no-build
./scripts/publish.ps1
```

Для среды с ограниченным MSBuild worker-процессом: `dotnet build PathFlux.slnx -c Release --no-restore -m:1 -nr:false -p:UseSharedCompilation=false`. В данной sandbox-среде VSTest зависал на запуске IPC; повторный прогон вне sandbox работает. Это ограничение среды, не успешный тест. GitHub Actions настроен на обычный Windows runner; облачный CI в этой сессии не запускался.

Сборка помещает сетевой агент в `PathFlux/bin/Release/net10.0/agent/`. Publish-скрипт публикует приложение и агента раздельно, затем собирает portable-папку `artifacts/win-x64`. Не перемещать только UI EXE: нужны зависимости и каталог agent. Runtime framework-dependent .NET 10 x64; движок отдельно.

## Дополнительная проверка официального движка

```powershell
$installed = ./scripts/get-engine.ps1
$env:PATHFLUX_TEST_ENGINE = $installed.EnginePath
dotnet test tests/PathFlux.Engine.Tests/PathFlux.Engine.Tests.csproj -c Release
```

Без PATHFLUX_TEST_ENGINE внешняя проверка помечается Skipped. Она проверяет hash и `check`, не создаёт TUN, не требует UAC и не изменяет маршруты. Остальные тесты используют локальный SOCKS/HTTP-сервер, временные файлы и DPAPI этого Windows-пользователя. Сетевой upstream для них не нужен. Проверка сертификатов TLS испытывается на недоверенном локальном сертификате (ожидаемый отказ).

## Ручная проверка

Запуск UI: `PathFlux.exe --smoke-test` создаёт реальное окно и завершает его автоматически, без изменения пользовательских настроек. Для функционального acceptance использовать шаги network-design.md: два процесса/два пути/разные маршруты, priority, отключение правила, proxy outage, авария агента, сеть после остановки. До его выполнения этапы 0/1 имеют статус Partial. Результаты автоматического прогона приведены в verification.md.

Новые outbounds добавляются сначала в доменную модель/валидатор/capabilities, затем в генератор и диагностические тесты, и только после этого в форму. Не добавлять неработающие переключатели UDP/PID/kill switch. Схема JSON=1; неизвестная будущая схема не перезаписывается.
