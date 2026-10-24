# PathFlux

Windows 10/11 x64 desktop-клиент выборочного проксирования на C# / .NET 10 / Avalonia. Первая итерация по этапам 0–1: реальные формы профилей и правил, процессы, DPAPI, атомарный JSON, TCP-диагностика, компилятор sing-box и отдельный агент с UAC.

**Состояние: инженерный MVP, сетевой acceptance ещё не завершён.** Генерация JSON и успешный `sing-box check` не подтверждают selective routing. Включение TUN требует ручной проверки на Windows. UDP через правила Proxy блокируется, точный PID и системный kill switch недоступны. Полная [матрица возможностей](docs/limitations.md).

![Интерфейс PathFlux](docs/images/overview.png)

## Сборка и запуск

Требуется Windows x64 и .NET SDK 10.0.401 (закреплён в global.json).

```powershell
dotnet restore PathFlux.slnx
dotnet build PathFlux.slnx -c Release
dotnet test PathFlux.slnx -c Release --no-build
dotnet run --project PathFlux/PathFlux.csproj -c Release --no-build
```

UI запускается с обычными правами. Сборка автоматически кладёт агент в `agent/` рядом с приложением. Только кнопка запуска движка вызывает UAC для отдельного агента. Для portable-папки: `./scripts/publish.ps1`; требуется .NET Runtime 10 x64.

## Первая настройка

1. Выполнить `./scripts/get-engine.ps1`: скрипт получает **официальный sing-box 1.12.12 Windows amd64**, проверяет архив и EXE по закреплённым SHA-256. Бинарник не включён в Git и publish.
2. В «Настройки» указать полученный полный путь к `sing-box.exe` и SHA-256 EXE: `f1e6453b62482a95c9461d2c84d8e1a95567609f739adf6a1227a9b96c578747`. Сохранить.
3. В «Прокси» добавить свой SOCKS5 или HTTP/HTTPS CONNECT. `127.0.0.1:1080` — только пример; приложение не устанавливает и не перенастраивает OpenVPN/Docker.
4. В «Диагностика» проверить TCP CONNECT к выбранной цели. UDP ASSOCIATE проверяет только согласование, передача UDP остаётся NotVerified.
5. В «Процессы» выбрать процессы и создать постоянное TCP-правило по имени/пути. Либо создать правило вручную. Меньший приоритет применяется первым, UUID разрешает равенства.
6. Проверить конфигурацию и запустить агент. TUN затрагивает системные маршруты; сначала ознакомиться с [сетевой проверкой и recovery](docs/network-design.md). Статус Degraded честно сохраняется до подтверждённой сетевой приёмки.

Профили и правила хранятся в `%LOCALAPPDATA%/PathFlux/config.json`; пароли — в отдельном DPAPI-хранилище этого пользователя. Изменение настроек во время работы запрещено: остановить → сохранить → запустить. Необработанная конфигурация движка и его stderr с возможными секретами на диск не пишутся.

## Документация

- [Архитектура](docs/architecture.md), [решение по движку и зависимости](docs/adr-001-engine.md).
- [Команды разработки и проверки](docs/development.md).
- [Сеть и ручной acceptance](docs/network-design.md), [план PID/WFP](docs/adr-002-process-instance-attribution.md).
- [Безопасность](docs/security.md), [ограничения](docs/limitations.md), [этапы](docs/milestones.md).

Исходный код PathFlux: MIT. sing-box распространяется отдельно по его собственной лицензии; [условия и источники зависимостей](docs/adr-001-engine.md). Автообновлений, телеметрии и облачной регистрации нет.
