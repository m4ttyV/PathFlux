using System.Net;
using System.Text.RegularExpressions;
using PathFlux.Domain;

namespace PathFlux.Application;

/// <summary>Validates persisted policy without reading files or invoking a privileged engine.</summary>
public static class ConfigurationValidator
{
    public static ConfigValidationResult ValidateEngineActivation(ProxyConfiguration configuration)
    {
        var issues = Validate(configuration).Issues.ToList();
        if (configuration.Settings?.ExperimentalProcessTrees == true && configuration.Rules is not null)
            foreach (var rule in configuration.Rules.Where(r => r is not null && r.Enabled && (r.IncludeChildren || r.Selector?.Kind == SelectorKind.ProcessInstance) && r.Network != NetworkTransport.Tcp))
                issues.Add(new("tree.udp.notVerified", "UDP для точного дерева PID ещё не прошёл сетевую приёмку. Для дерева выберите TCP; обычные UDP-правила не изменяются.", rule.Id));
        return new(issues);
    }
    public static ConfigValidationResult Validate(ProxyConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        var issues = ValidatePolicy(configuration.Rules, configuration.Profiles, configuration.Settings?.ExperimentalProcessTrees == true).Issues.ToList();
        if (configuration.SchemaVersion is not (1 or 2))
            issues.Add(new("schema.unsupported", "Поддерживаются схемы конфигурации 1 и 2."));
        if (configuration.DefaultAction != RouteAction.Direct)
            issues.Add(new("default.unsupported", "В этой версии маршрут по умолчанию должен быть Direct."));
        if (configuration.Settings is null)
            issues.Add(new("settings.required", "Отсутствуют настройки приложения."));
        else
        {
            if (configuration.Settings.ExperimentalProcessTrees)
            {
                if (configuration.SchemaVersion != 2) issues.Add(new("tree.schema", "Дерево PID требует схемы 2."));
                issues.Add(new("tree.experimental", "Дерево PID Experimental: отдельная сборка движка, неизвестная принадлежность блокируется. Для UDP приёмка не завершена.", IsWarning: true));
            }
            if (configuration.Settings.ProcessRefreshSeconds is < 1 or > 3600)
                issues.Add(new("settings.refresh", "Интервал обновления процессов должен быть от 1 до 3600 секунд."));
            if (configuration.Settings.DnsMode != "System")
                issues.Add(new("dns.unsupported", "В этой версии доступен только режим System DNS; защищённый DNS-маршрут не подтверждён."));
            if (configuration.Settings.ExperimentalSocksUdp)
            {
                if (configuration.SchemaVersion != 2) issues.Add(new("udp.schema", "Экспериментальный UDP требует схемы 2."));
                foreach (var rule in configuration.Rules?.Where(r => r is not null && ExperimentalUdpPolicy.UsesUdp(r)) ?? [])
                {
                    var profile = configuration.Profiles?.FirstOrDefault(p => p?.Id == rule.ProfileId);
                    if (profile is not null && ExperimentalUdpPolicy.Incompatibility(profile) is { } reason)
                        issues.Add(new("udp.incompatible", reason, rule.Id));
                }
                issues.RemoveAll(i => i.Code == "udp.unverified");
                issues.Add(new("udp.experimental", "Экспериментальный UDP включён вручную. Стабильность Discord и отсутствие DNS-утечек не подтверждены.", IsWarning: true));
            }
        }
        return new(issues);
    }

    public static ConfigValidationResult ValidatePolicy(IReadOnlyList<RoutingRule>? rules, IReadOnlyList<ProxyProfile>? profiles, bool processTrees = false)
    {
        var issues = new List<ValidationIssue>();
        if (profiles is null) issues.Add(new("profiles.required", "Отсутствует список профилей."));
        if (rules is null) issues.Add(new("rules.required", "Отсутствует список правил."));
        if (rules is null || profiles is null) return new(issues);

        var profileIds = new HashSet<Guid>();
        var availableProfiles = new Dictionary<Guid, ProxyProfile>();
        foreach (var profile in profiles)
        {
            if (profile is null)
            {
                issues.Add(new("profile.required", "Список профилей содержит пустой элемент."));
                continue;
            }
            if (profile.Id == Guid.Empty || !profileIds.Add(profile.Id))
                issues.Add(new("profile.id", "Идентификаторы профилей должны быть непустыми и уникальными."));
            else
                availableProfiles.Add(profile.Id, profile);
            ValidateProfile(profile, issues);
        }

        var ruleIds = new HashSet<Guid>();
        foreach (var rule in rules)
        {
            if (rule is null)
            {
                issues.Add(new("rule.required", "Список правил содержит пустой элемент."));
                continue;
            }
            if (rule.Id == Guid.Empty || !ruleIds.Add(rule.Id))
                issues.Add(new("rule.id", "Идентификаторы правил должны быть непустыми и уникальными.", rule.Id));
            if (!IsNameValid(rule.Name))
                issues.Add(new("rule.name", "Имя правила должно содержать от 1 до 120 символов без управляющих символов.", rule.Id));

            // Disabled rules remain editable drafts, but cannot affect a compiled routing table.
            if (!rule.Enabled) continue;
            ValidateRule(rule, availableProfiles, issues, processTrees);
        }
        return new(issues);
    }

    private static void ValidateProfile(ProxyProfile profile, List<ValidationIssue> issues)
    {
        if (profile.UseTlsServerNameForTcp && profile.Protocol != ProxyProtocol.Socks5)
            issues.Add(new("profile.tcpSni", "Режим TCP через TLS/SNI поддерживается только для SOCKS5."));
        if (profile.UseTlsServerNameForTcp && (!Uri.TryCreate(profile.TcpIpv4DohServer, UriKind.Absolute, out var doh) || doh.Scheme != "https" ||
            !IPAddress.TryParse(doh.Host, out var address) || address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork ||
            !ExperimentalUdpPolicy.IsUnicast(address) || doh.UserInfo.Length != 0 || doh.Query.Length != 0 || doh.Fragment.Length != 0))
            issues.Add(new("profile.tcpDoh", "Для TCP/IPv4 укажите HTTPS DoH JSON endpoint с буквальным IPv4, без логина, параметров или фрагмента."));
        if (!IsNameValid(profile.Name))
            issues.Add(new("profile.name", "Имя профиля должно содержать от 1 до 120 символов без управляющих символов."));
        if (!Enum.IsDefined(profile.Protocol))
            issues.Add(new("profile.protocol", "Неподдерживаемый тип прокси."));
        if (!IsHostValid(profile.Host))
            issues.Add(new("profile.host", "Укажите DNS-имя или IP-адрес прокси без схемы, порта, пути и учётных данных."));
        if (profile.Port is < 1 or > 65535)
            issues.Add(new("profile.port", "Порт прокси должен быть от 1 до 65535."));
        if (!Enum.IsDefined(profile.UdpRelayMode)) issues.Add(new("udp.mode", "Неизвестный режим UDP relay."));
        if (profile.UdpRelayMode == UdpRelayMode.DockerNat)
        {
            if (ExperimentalUdpPolicy.Incompatibility(profile) is { } reason) issues.Add(new("udp.docker.host", reason));
            if (profile.UdpPublishedPortFirst is not >= 1 or > 65535 || profile.UdpPublishedPortLast is not >= 1 or > 65535 ||
                profile.UdpPublishedPortFirst > profile.UdpPublishedPortLast)
                issues.Add(new("udp.docker.range", "Для Docker NAT укажите разрешённый диапазон UDP-портов от 1 до 65535, начало не больше конца."));
        }
        else if (profile.UdpPublishedPortFirst is not null || profile.UdpPublishedPortLast is not null)
            issues.Add(new("udp.standard.range", "Диапазон опубликованных портов применяется только к Docker NAT."));
        if (profile.CredentialsRef is not null &&
            (string.IsNullOrWhiteSpace(profile.CredentialsRef) || profile.CredentialsRef.Any(char.IsControl)))
            issues.Add(new("profile.credentials", "Ссылка на защищённое хранилище учётных данных некорректна."));
        if (!string.IsNullOrEmpty(profile.TlsServerName))
        {
            if (profile.Protocol != ProxyProtocol.HttpsConnect)
                issues.Add(new("profile.tls.protocol", "TLS Server Name применим только к HTTPS CONNECT."));
            if (!IsHostValid(profile.TlsServerName))
                issues.Add(new("profile.tls.name", "TLS Server Name должен быть корректным именем сервера или IP-адресом."));
        }
    }

    private static void ValidateRule(RoutingRule rule, IReadOnlyDictionary<Guid, ProxyProfile> profiles, List<ValidationIssue> issues, bool processTrees)
    {
        void Error(string code, string message) => issues.Add(new(code, message, rule.Id));
        if (!Enum.IsDefined(rule.Network)) Error("rule.network", "Неподдерживаемый сетевой транспорт.");
        if (!Enum.IsDefined(rule.Action)) Error("rule.action", "Неподдерживаемое действие правила.");
        if (!Enum.IsDefined(rule.OnProxyFailure)) Error("rule.failure", "Неподдерживаемая политика сбоя прокси.");
        if (!Enum.IsDefined(rule.Lifetime)) Error("rule.lifetime", "Неподдерживаемый срок действия правила.");
        if (rule.IncludeChildren && !processTrees) Error("children.unsupported", "Для дерева процессов нужен экспериментальный backend PathFlux Process Tree.");
        if (rule.IncludeChildren && processTrees && rule.Selector?.Kind != SelectorKind.ProcessInstance)
            Error("children.root", "Для точного дерева выберите корневой PID с временем создания через список процессов.");
        if (rule.Lifetime == RuleLifetime.UntilProcessExit)
            Error("lifetime.unsupported", "Одноразовые правила требуют подтверждённой атрибуции экземпляра процесса и пока недоступны.");

        if (rule.Selector is null)
            Error("selector.required", "Не выбран процесс или путь EXE.");
        else
        {
            if (!Enum.IsDefined(rule.Selector.Kind)) Error("selector.kind", "Неподдерживаемый селектор процесса.");
            else if (rule.Selector.Kind == SelectorKind.ProcessInstance && !processTrees)
                Error("pid.unsupported", "Точный PID не поддерживается; выберите постоянное правило по имени или пути EXE.");
            else if (rule.Selector.Kind == SelectorKind.ProcessInstance)
            {
                if (rule.Selector.Instance is not { Pid: > 4, SequenceNumber: > 0 } instance || instance.StartTimeUtc == default ||
                    instance.StartTimeUtc.UtcTicks <= DateTime.FromFileTimeUtc(0).Ticks ||
                    rule.Selector.Value != instance.Pid.ToString(System.Globalization.CultureInfo.InvariantCulture))
                    Error("pid.identity", "Для точного PID нужны согласованные PID и время создания из списка процессов.");
            }
            else
            {
                if (rule.Selector.Instance is not null)
                    Error("selector.instance", "Постоянное правило по имени или пути не должно содержать экземпляр PID.");
                if (rule.Selector.Kind == SelectorKind.ProcessName && !IsProcessNameValid(rule.Selector.Value))
                    Error("selector.name", "Укажите только имя EXE, например Discord.exe, без пути и шаблонов.");
                if (rule.Selector.Kind == SelectorKind.ExecutablePath && !IsExecutablePathValid(rule.Selector.Value))
                    Error("selector.path", "Укажите абсолютный Windows-путь к EXE без переменных и шаблонов.");
            }
        }

        if (rule.Action != RouteAction.Proxy)
        {
            if (rule.ProfileId is not null)
                Error("rule.profile.unexpected", "Профиль применяется только к действию Proxy.");
            return;
        }

        if (rule.OnProxyFailure == FailurePolicy.Direct)
            Error("fallback.unsupported", "Direct fallback при сбое прокси пока не реализован; выберите Block.");
        if (rule.ProfileId is null || !profiles.TryGetValue(rule.ProfileId.Value, out var profile))
            Error("rule.profile.missing", "Для Proxy требуется существующий профиль.");
        else if (!profile.Enabled)
            Error("rule.profile.disabled", "Правило ссылается на отключённый профиль.");
        else if (rule.Network is NetworkTransport.Udp or NetworkTransport.Both)
            issues.Add(new("udp.unverified", "Прозрачная передача UDP через TUN не подтверждена. Совпавшие UDP-потоки будут отклонены без скрытого Direct fallback.", rule.Id, true));
    }

    private static bool IsNameValid(string? name) => !string.IsNullOrWhiteSpace(name) && name.Length <= 120 && !name.Any(char.IsControl);

    private static bool IsHostValid(string? host)
    {
        if (string.IsNullOrWhiteSpace(host) || host.Length > 253 || host.Any(char.IsWhiteSpace) || host.Any(char.IsControl)) return false;
        if (host.IndexOfAny(['/', '\\', '@', '[', ']', '?', '#']) >= 0) return false;
        if (IPAddress.TryParse(host, out _)) return true;
        return !host.Contains(':') && Uri.CheckHostName(host) == UriHostNameType.Dns;
    }

    private static bool IsProcessNameValid(string? name) =>
        !string.IsNullOrWhiteSpace(name) && name.Length <= 260 && name == name.Trim() &&
        name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) && name.Length > 4 &&
        !name.Any(char.IsControl) && name.IndexOfAny(['/', '\\', ':', '*', '?', '"', '<', '>', '|']) < 0;

    private static bool IsExecutablePathValid(string? path)
    {
        if (string.IsNullOrWhiteSpace(path) || path != path.Trim() || path.Length > 32767 ||
            !path.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) || path.Any(char.IsControl) ||
            path.IndexOfAny(['*', '?', '"', '<', '>', '|', '%']) >= 0) return false;
        var normalized = path.Replace('/', '\\');
        var drivePath = Regex.IsMatch(normalized, @"^[A-Za-z]:\\[^\\]");
        var uncPath = Regex.IsMatch(normalized, @"^\\\\[^\\:]+\\[^\\:]+\\[^\\]");
        if (!drivePath && !uncPath) return false;
        var afterRoot = drivePath ? normalized[2..] : normalized;
        return !afterRoot.Contains(':') && !normalized.Split('\\').Any(part => part is "." or "..");
    }
}
