# ADR 001 — внешний движок и закреплённые зависимости

Дополнение 24.10.2026: требование единственного EXE 1.12.12 заменено поддержкой версий от 1.12.2 с проверкой пользовательского SHA-256, версии/платформы и `sing-box check`. Загрузка проверяет официальный архив по метаданным GitHub. Подробности: [совместимость движка](engine-compatibility.md). Исследование ниже описывает первоначальный выбор 1.12.12; его выводы о DNS/Wintun нельзя автоматически переносить на все будущие версии без приёмки.

24.10.2026. Решение: sing-box как отдельный процесс, собственная доменная модель и отдельный генератор. Не реализовывать TCP/IP стек и сложные proxy-протоколы. WinDivert отсутствует. Windows-параметры TUN: auto_route, auto_detect_interface, process_name / process_path, Direct по умолчанию. Linux auto_redirect/UID/iptables не используются.

## Проверенные источники

- [sing-box v1.12.12 options TUN](https://github.com/SagerNet/sing-box/blob/v1.12.12/option/tun.go), [route](https://github.com/SagerNet/sing-box/blob/v1.12.12/option/route.go), [actions](https://github.com/SagerNet/sing-box/blob/v1.12.12/option/rule_action.go). Закреплена конкретная проверяемая версия, а не обещана совместимость с любым новым JSON. Текущая [документация](https://sing-box.sagernet.org/configuration/route/rule/) может описывать новые поля, поэтому адаптер сверяется также с исходниками тега.
- [stdin configuration](https://github.com/SagerNet/sing-box/blob/v1.12.12/cmd/sing-box/cmd_run.go): `check -c stdin`, `run -c stdin`, без временного файла с паролями.
- DNS Windows: sing-tun назначает DNS нового адаптера, поэтому обязательный hijack только виртуальных адресов TUN добавлен в таблицу. [Pinned local resolver](https://github.com/SagerNet/sing-box/blob/v1.12.12/dns/transport/local/resolv_windows.go) исключает MyInterface, а local transport использует direct dialer. Это устраняет известную конфигурационную петлю по исходникам; сетевой тест остаётся открытым.
- [Официальный релиз](https://github.com/SagerNet/sing-box/releases/tag/v1.12.12), [метаданные asset API](https://api.github.com/repos/SagerNet/sing-box/releases/tags/v1.12.12). Архив Windows amd64 SHA-256 `352c69526b76cd199539c0e02b4042d1acc109cde3a0a671a40af4e24290faa4`; распакованный EXE `f1e6453b62482a95c9461d2c84d8e1a95567609f739adf6a1227a9b96c578747`. Эти значения сверены в рабочем окружении. `version` сообщил 1.12.12, windows/amd64, revision 54ed58499d7063136ed52dabf87d179d252425d0. `check` принял конфигурацию; `run` с TUN не запускался.
- [go.mod тега](https://github.com/SagerNet/sing-box/blob/v1.12.12/go.mod) закрепляет sing-tun v0.7.3. Его [Wintun loader](https://github.com/SagerNet/sing-tun/blob/v0.7.3/internal/wintun/dll_windows.go) загружает встроенное содержимое DLL через memmod. Добавлять случайный wintun.dll рядом с приложением не требуется. Драйвер всё равно требует Windows-проверки прав, подписи и совместимости; отсутствие предупреждений защиты не гарантируется.

## Зависимости и лицензии

| Компонент | Версия | Условия / роль |
|---|---|---|
| .NET SDK | 10.0.401 | Установленный SDK, LTS .NET 10; [поддержка](https://dotnet.microsoft.com/en-us/platform/support/policy/dotnet-core) |
| Avalonia / Desktop / Fluent / Inter | 11.3.11 | Существующая версия проекта; [MIT](https://github.com/AvaloniaUI/Avalonia/blob/11.3.11/licence.md); Windows native desktop |
| CommunityToolkit.Mvvm | 8.2.1 | Существующая версия, MVVM generators, MIT |
| Tmds.DBus.Protocol | 0.21.3 | Явно закреплён backport исправления [GHSA-xrw6-gwf8-vvr9](https://github.com/advisories/GHSA-xrw6-gwf8-vvr9) вместо уязвимой 0.21.2 из Avalonia |
| sing-box | 1.12.12 official Windows x64 | [GPL-3.0-or-later и дополнительное условие имени](https://github.com/SagerNet/sing-box/blob/v1.12.12/LICENSE); отдельная загрузка, не переименовывается в PathFlux |
| Wintun | Встроенная зависимость закреплённого движка | [Официальная лицензия и подпись](https://www.wintun.net/); отдельная установка драйверов PathFlux отсутствует |
| xUnit / VS runner / Test SDK | 2.9.3 / 3.1.1 / 17.14.1 | Только тесты |

Наш код MIT не меняет условия сторонних компонентов. При будущей поставке sing-box вместе с установщиком необходимо сохранить его notices, лицензию, доступность соответствующего исходного кода и выполнить остальные условия распространения выбранной версии. Текущий publish не включает движок. При обновлении EXE пользователь меняет путь и SHA-256; изменения схемы генератора и сетевого поведения требуют отдельной проверки совместимости и acceptance.
