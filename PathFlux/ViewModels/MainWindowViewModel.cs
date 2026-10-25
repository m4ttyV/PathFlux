using System.Collections.ObjectModel;
using System.Net;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using PathFlux.Application;
using PathFlux.Domain;

namespace PathFlux.ViewModels;

public partial class MainWindowViewModel(IConfigurationStore store, ISecretStore secrets,
    IProcessDiscoveryService discovery, IProxyDiagnostics diagnostics, IProxyEngineAdapter engine, IEngineInstaller? engineInstaller = null)
    : ViewModelBase, IAsyncDisposable
{
    private readonly CancellationTokenSource _lifetime = new();
    private ProxyConfiguration _configuration = new();
    private Task? _pollTask;
    private IReadOnlyList<ProcessInfo> _processSnapshot = [];
    private EngineState _state = EngineState.Stopped;
    private bool _disposed;
    private TaskCompletionSource? _operationFinished;

    public ObservableCollection<ProxyProfile> Profiles { get; } = [];
    public ObservableCollection<RoutingRule> Rules { get; } = [];
    public ObservableCollection<ProcessInfo> Processes { get; } = [];
    public ObservableCollection<ProcessInfo> SelectedProcesses { get; } = [];
    public ObservableCollection<string> LogEntries { get; } = [];
    public ProxyProtocol[] Protocols { get; } = Enum.GetValues<ProxyProtocol>();
    public SelectorKind[] Selectors => ExperimentalProcessTrees ? [SelectorKind.ProcessName, SelectorKind.ExecutablePath, SelectorKind.ProcessInstance] : [SelectorKind.ProcessName, SelectorKind.ExecutablePath];
    public string[] SelectorNames => ExperimentalProcessTrees ? ["По имени файла приложения", "По полному пути к приложению", "Конкретный процесс (PID)"] : ["По имени файла приложения", "По полному пути к приложению"];
    public int RuleSelectorIndex { get => (int)RuleSelector; set { if (value >= 0 && value < Selectors.Length) RuleSelector = (SelectorKind)value; } }
    public NetworkTransport[] Networks { get; } = Enum.GetValues<NetworkTransport>();
    public UdpRelayMode[] UdpRelayModes { get; } = Enum.GetValues<UdpRelayMode>();
    public string[] UdpRelayModeNames { get; } = ["Адрес, выданный SOCKS5-сервером", "Docker: указать опубликованные порты", "Автоматически (рекомендуется)"];
    public string[] NetworkNames { get; } = ["TCP", "UDP", "TCP + UDP"];
    public int ProfileUdpModeIndex { get => (int)ProfileUdpRelayMode; set { if (value is >= 0 and <= 2) ProfileUdpRelayMode = (UdpRelayMode)value; } }
    public int RuleNetworkIndex { get => (int)RuleNetwork; set { if (value is >= 0 and <= 2) RuleNetwork = (NetworkTransport)value; } }
    public RouteAction[] Actions { get; } = Enum.GetValues<RouteAction>();
    public string[] ActionNames { get; } = ["Напрямую", "Заблокировать", "Через прокси"];
    public int RuleActionIndex { get => (int)RuleAction; set { if (value is >= 0 and <= 2) RuleAction = (RouteAction)value; } }
    public string[] ProcessSortOptions { get; } = ["Имя", "PID", "Путь"];
    public string[] Themes { get; } = ["Dark", "Light", "System"];
    public event Action<string>? ThemeChanged;

    [ObservableProperty] private bool _isBusy;
    [ObservableProperty] private bool _isInitialized;
    [ObservableProperty] private string _notice = "Загрузка настроек…";
    [ObservableProperty] private string _statusText = "Остановлен";
    [ObservableProperty] private string _statusDetail = "Движок ещё не запускался.";
    [ObservableProperty] private string _validationText = "Проверка конфигурации ещё не выполнялась.";
    [ObservableProperty] private string _capabilityText = "Загрузка возможностей адаптера…";
    [ObservableProperty] private int _selectedTab;
    [ObservableProperty] private ProxyProfile? _selectedProfile;
    [ObservableProperty] private string _profileName = "Новый прокси";
    [ObservableProperty] private ProxyProtocol _profileProtocol = ProxyProtocol.Socks5;
    [ObservableProperty] private string _profileHost = "127.0.0.1";
    [ObservableProperty] private string _profilePort = "1080";
    [ObservableProperty] private UdpRelayMode _profileUdpRelayMode = UdpRelayMode.Auto;
    [ObservableProperty] private bool _profileUseTlsServerNameForTcp = true;
    [ObservableProperty] private string _profileTcpIpv4DohServer = "https://1.1.1.1/dns-query";
    [ObservableProperty] private string _profileUdpPortFirst = "";
    [ObservableProperty] private string _profileUdpPortLast = "";
    [ObservableProperty] private bool _profileEnabled = true;
    [ObservableProperty] private string _profileTlsServerName = "";
    [ObservableProperty] private string _profileUsername = "";
    [ObservableProperty] private string _profilePassword = "";
    [ObservableProperty] private bool _replaceCredentials;
    [ObservableProperty] private bool _removeCredentials;
    [ObservableProperty] private string _credentialStatus = "Авторизация не сохранена.";
    [ObservableProperty] private RoutingRule? _selectedRule;
    [ObservableProperty] private string _ruleName = "";
    [ObservableProperty] private bool _ruleEnabled = true;
    [ObservableProperty] private bool _ruleIncludeChildren;
    [ObservableProperty] private string _rulePriority = "100";
    [ObservableProperty] private SelectorKind _ruleSelector = SelectorKind.ProcessName;
    [ObservableProperty] private string _ruleValue = "";
    [ObservableProperty] private NetworkTransport _ruleNetwork = NetworkTransport.Tcp;
    [ObservableProperty] private RouteAction _ruleAction = RouteAction.Proxy;
    [ObservableProperty] private ProxyProfile? _ruleProfile;
    [ObservableProperty] private string _processSearch = "";
    [ObservableProperty] private string _processSort = "Имя";
    [ObservableProperty] private string _processSummary = "Список ещё не обновлён.";
    [ObservableProperty] private ProxyProfile? _diagnosticProfile;
    [ObservableProperty] private string _targetHost = "example.com";
    [ObservableProperty] private string _targetPort = "443";
    [ObservableProperty] private string _udpEchoHost = "";
    [ObservableProperty] private string _udpEchoPort = "";
    [ObservableProperty] private string _diagnosticText = "Проверка ещё не выполнялась. TCP CONNECT не доказывает работу TUN или UDP.";
    [ObservableProperty] private string _enginePath = "";
    [ObservableProperty] private string _engineSha256 = "";
    [ObservableProperty] private string _selectedTheme = "Dark";
    [ObservableProperty] private bool _bypassLan;
    [ObservableProperty] private string _refreshSeconds = "5";
    [ObservableProperty] private bool _experimentalSocksUdp;
    [ObservableProperty] private bool _experimentalProcessTrees;
    partial void OnExperimentalProcessTreesChanged(bool value) { OnPropertyChanged(nameof(Selectors)); OnPropertyChanged(nameof(SelectorNames)); }
    [ObservableProperty] private string _liveUdpText = "UDP-посредники не запущены.";
    [ObservableProperty] private bool _isRecordingUdp;
    [ObservableProperty] private string _udpRecordingPath = "";
    private int _udpRecordedSamples;
    public bool IsSocks => ProfileProtocol == ProxyProtocol.Socks5;
    public bool ShowTcpIpv4Settings => IsSocks && ProfileUseTlsServerNameForTcp;
    partial void OnProfileUseTlsServerNameForTcpChanged(bool value) => OnPropertyChanged(nameof(ShowTcpIpv4Settings));
    public bool IsDockerNat => IsSocks && ProfileUdpRelayMode == UdpRelayMode.DockerNat;
    public string ProfileUdpModeSummary => UdpRelayModeNames[(int)ProfileUdpRelayMode];
    partial void OnProfileUdpRelayModeChanged(UdpRelayMode value) { OnPropertyChanged(nameof(IsDockerNat)); OnPropertyChanged(nameof(ProfileUdpModeIndex)); OnPropertyChanged(nameof(ProfileUdpModeSummary)); }
    partial void OnRuleNetworkChanged(NetworkTransport value) => OnPropertyChanged(nameof(RuleNetworkIndex));

    // Failed can still mean that network cleanup has not finished. Require Stop before editing.
    public bool EngineActive => _state != EngineState.Stopped;
    public bool CanEdit => IsInitialized && !IsBusy && !EngineActive;
    public bool CanStart => CanEdit;
    public bool CanStop => IsInitialized && !IsBusy && EngineActive;
    public bool CanUseTools => IsInitialized && !IsBusy;
    public bool IsHttps => ProfileProtocol == ProxyProtocol.HttpsConnect;
    public bool IsProxyAction => RuleAction == RouteAction.Proxy;
    public string RuleValuePlaceholder => RuleSelector switch
    {
        SelectorKind.ExecutablePath => "Полный путь к файлу приложения — удобнее выбрать во вкладке «Процессы»",
        SelectorKind.ProcessInstance => "Выберите главный процесс во вкладке «Процессы» и создайте дерево PID",
        _ => "Имя исполняемого файла приложения с расширением .exe"
    };
    partial void OnRuleSelectorChanged(SelectorKind value) { OnPropertyChanged(nameof(RuleValuePlaceholder)); OnPropertyChanged(nameof(RuleSelectorIndex)); }
    public string ProfileCount => Profiles.Count.ToString();
    public string RuleCount => Rules.Count.ToString();
    public string ProfileUdpStatus => SelectedProfile is { } profile
        ? ProfileEditorIdentityMatches(profile) ? DescribeUdp(profile)
            : "Параметры профиля изменены в форме. Сохраните профиль и повторите UDP echo-проверку."
        : "Новый профиль: передача UDP через relay ещё не проверялась.";
    public string DiagnosticUdpStatus => DiagnosticProfile is { } profile ? DescribeUdp(profile)
        : "Выберите профиль. Положительный UDP echo подтверждает только проверенный relay и цель.";
    public string EditingHint => EngineActive ? "Для изменения профилей, правил и настроек сначала остановите движок."
        : "Изменения сохраняются локально. Чтобы применить правила, запустите движок.";
    partial void OnIsBusyChanged(bool value) => NotifyPermissions();
    partial void OnIsInitializedChanged(bool value) => NotifyPermissions();
    partial void OnProfileProtocolChanged(ProxyProtocol value)
    { OnPropertyChanged(nameof(IsHttps)); OnPropertyChanged(nameof(IsSocks)); OnPropertyChanged(nameof(IsDockerNat)); OnPropertyChanged(nameof(ProfileUdpStatus)); OnPropertyChanged(nameof(ShowTcpIpv4Settings)); }
    partial void OnProfileHostChanged(string value) => OnPropertyChanged(nameof(ProfileUdpStatus));
    partial void OnProfilePortChanged(string value) => OnPropertyChanged(nameof(ProfileUdpStatus));
    partial void OnProfileTlsServerNameChanged(string value) => OnPropertyChanged(nameof(ProfileUdpStatus));
    partial void OnReplaceCredentialsChanged(bool value) => OnPropertyChanged(nameof(ProfileUdpStatus));
    partial void OnRemoveCredentialsChanged(bool value) => OnPropertyChanged(nameof(ProfileUdpStatus));
    partial void OnDiagnosticProfileChanged(ProxyProfile? value) => OnPropertyChanged(nameof(DiagnosticUdpStatus));
    partial void OnRuleActionChanged(RouteAction value) { OnPropertyChanged(nameof(IsProxyAction)); OnPropertyChanged(nameof(RuleActionIndex)); }
    partial void OnProcessSearchChanged(string value) => FilterProcesses();
    partial void OnProcessSortChanged(string value) => FilterProcesses();

    partial void OnSelectedProfileChanged(ProxyProfile? value)
    {
        var p = value;
        if (p is null) { OnPropertyChanged(nameof(ProfileUdpStatus)); return; }
        ProfileName = p.Name; ProfileProtocol = p.Protocol; ProfileHost = p.Host; ProfilePort = p.Port.ToString();
        ProfileEnabled = p.Enabled; ProfileTlsServerName = p.TlsServerName ?? "";
        ProfileUdpRelayMode = p.UdpRelayMode; ProfileUdpPortFirst = p.UdpPublishedPortFirst?.ToString() ?? ""; ProfileUdpPortLast = p.UdpPublishedPortLast?.ToString() ?? "";
        ProfileUseTlsServerNameForTcp = p.UseTlsServerNameForTcp;
        ProfileTcpIpv4DohServer = p.TcpIpv4DohServer;
        ClearCredentialEditor();
        CredentialStatus = p.CredentialsRef is null ? "Авторизация не сохранена."
            : "Авторизация защищена Windows DPAPI. Пароль не отображается.";
        OnPropertyChanged(nameof(ProfileUdpStatus));
    }
    partial void OnSelectedRuleChanged(RoutingRule? value)
    {
        var r = value;
        if (r is null) return;
        RuleName = r.Name; RuleEnabled = r.Enabled; RulePriority = r.Priority.ToString();
        RuleSelector = r.Selector.Kind; RuleValue = r.Selector.Value; RuleNetwork = r.Network; RuleAction = r.Action;
        RuleProfile = Profiles.FirstOrDefault(p => p.Id == r.ProfileId);
        RuleIncludeChildren = r.IncludeChildren;
    }

    public async Task InitializeAsync()
    {
        await RunAsync(async ct =>
        {
            _configuration = await store.LoadAsync(ct);
            LoadCollections();
            EnginePath = _configuration.Settings.EnginePath;
            EngineSha256 = _configuration.Settings.EngineSha256;
            SelectedTheme = _configuration.Settings.Theme;
            BypassLan = _configuration.Settings.BypassLan;
            ExperimentalSocksUdp = _configuration.Settings.ExperimentalSocksUdp;
            ExperimentalProcessTrees = _configuration.Settings.ExperimentalProcessTrees;
            RefreshSeconds = _configuration.Settings.ProcessRefreshSeconds.ToString();
            ThemeChanged?.Invoke(SelectedTheme);
            var c = await engine.GetCapabilitiesAsync(ct);
            CapabilityText = $"Правила по имени: {CapabilityLabel(c.ProcessName)} · по пути: {CapabilityLabel(c.ExecutablePath)}\nTCP: {CapabilityLabel(c.Tcp)} · UDP: {CapabilityLabel(c.Udp)} (SOCKS5, включается в настройках)\nДочерние процессы: Experimental, только TCP\nСистемный kill switch: {CapabilityLabel(c.KillSwitch)}. DNS: системный.";
            await RefreshProcessesCoreAsync(ct);
            await UpdateStatusAsync(ct);
            IsInitialized = true;
            Notice = "Готово. Маршрутизация по имени/пути требует проверки на этой Windows.";
        });
        if (IsInitialized && !_disposed) _pollTask = PollAsync(_lifetime.Token);
    }

    [RelayCommand] private void NewProfile()
    {
        if (!CanEdit) return;
        SelectedProfile = null; ProfileName = "Новый прокси"; ProfileProtocol = ProxyProtocol.Socks5;
        ProfileHost = "127.0.0.1"; ProfilePort = "1080"; ProfileEnabled = true; ProfileTlsServerName = "";
        ProfileUdpRelayMode = UdpRelayMode.Auto; ProfileUdpPortFirst = ""; ProfileUdpPortLast = ""; ProfileUseTlsServerNameForTcp = true; ProfileTcpIpv4DohServer = "https://1.1.1.1/dns-query";
        ClearCredentialEditor(); CredentialStatus = "Авторизация не сохранена.";
    }
    [RelayCommand] private Task SaveProfileAsync() => RunAsync(async ct =>
    {
        RequireStopped();
        if (string.IsNullOrWhiteSpace(ProfileName) || string.IsNullOrWhiteSpace(ProfileHost))
            throw new EditorValidationException("Укажите название и хост профиля.");
        if (!int.TryParse(ProfilePort, out var port) || port is < 1 or > 65535)
            throw new EditorValidationException("Порт должен быть числом от 1 до 65535.");
        int? first = null, last = null;
        if (IsDockerNat)
        {
            if (!int.TryParse(ProfileUdpPortFirst, out int begin) || !int.TryParse(ProfileUdpPortLast, out int end) || begin < 1 || end > 65535 || begin > end)
                throw new EditorValidationException("Укажите корректный диапазон опубликованных UDP-портов: 1–65535, начало не больше конца.");
            first = begin; last = end;
        }
        if (ReplaceCredentials && RemoveCredentials) throw new EditorValidationException("Выберите замену либо удаление авторизации.");
        if (ReplaceCredentials && string.IsNullOrEmpty(ProfileUsername)) throw new EditorValidationException("Укажите логин для авторизации.");
        var previous = SelectedProfile;
        string? newReference = null;
        var reference = previous?.CredentialsRef;
        if (ReplaceCredentials) reference = newReference = await secrets.StoreAsync(new(ProfileUsername, ProfilePassword), ct);
        else if (RemoveCredentials) reference = null;
        var p = new ProxyProfile
        {
            Id = previous?.Id ?? Guid.NewGuid(), Name = ProfileName.Trim(), Enabled = ProfileEnabled,
            Protocol = ProfileProtocol, Host = ProfileHost.Trim(), Port = port, CredentialsRef = reference,
            TlsServerName = IsHttps && !string.IsNullOrWhiteSpace(ProfileTlsServerName) ? ProfileTlsServerName.Trim() : null,
            UdpRelayMode = IsSocks ? ProfileUdpRelayMode : UdpRelayMode.Standard, UdpPublishedPortFirst = first, UdpPublishedPortLast = last,
            UseTlsServerNameForTcp = IsSocks && ProfileUseTlsServerNameForTcp, TcpIpv4DohServer = ProfileTcpIpv4DohServer.Trim()
        };
        if (previous is not null && UdpVerificationPolicy.Fingerprint(previous) == UdpVerificationPolicy.Fingerprint(p))
            p = p with { UdpVerification = previous.UdpVerification };
        var next = _configuration with { Profiles = _configuration.Profiles.Where(x => x.Id != p.Id).Append(p).ToList() };
        try { await PersistAsync(next, ct); }
        catch { if (newReference is not null) await TryDeleteSecretAsync(newReference, CancellationToken.None); throw; }
        SelectedProfile = Profiles.First(x => x.Id == p.Id);
        if (previous?.CredentialsRef is { } old && old != reference) await DeleteIfUnusedAsync(old, ct);
        Notice = "Профиль сохранён. Секреты хранятся отдельно под защитой Windows DPAPI.";
        AddLog("Профиль сохранён.");
    }, true);
    [RelayCommand] private Task DeleteProfileAsync() => RunAsync(async ct =>
    {
        RequireStopped();
        var p = SelectedProfile ?? throw new EditorValidationException("Выберите профиль.");
        if (_configuration.Rules.Any(r => r.ProfileId == p.Id))
            throw new EditorValidationException("Профиль используется правилами. Сначала измените или удалите эти правила.");
        await PersistAsync(_configuration with { Profiles = _configuration.Profiles.Where(x => x.Id != p.Id).ToList() }, ct);
        if (p.CredentialsRef is { } reference) await DeleteIfUnusedAsync(reference, ct);
        SelectedProfile = null; ClearCredentialEditor(); Notice = "Профиль удалён.";
    }, true);
    [RelayCommand] private void DuplicateProfile()
    {
        if (!CanEdit || SelectedProfile is null) return;
        var name = SelectedProfile.Name;
        SelectedProfile = null; ProfileName = name + " — копия"; ClearCredentialEditor();
        CredentialStatus = "Копия не включает авторизацию. При необходимости задайте её заново.";
    }
    [RelayCommand] private void NewRule()
    {
        if (!CanEdit) return;
        SelectedRule = null; RuleName = ""; RuleEnabled = true; RulePriority = "100";
        RuleSelector = SelectorKind.ProcessName; RuleValue = ""; RuleNetwork = NetworkTransport.Tcp;
        RuleIncludeChildren = false;
        RuleAction = RouteAction.Proxy; RuleProfile = Profiles.FirstOrDefault();
    }
    [RelayCommand] private Task SaveRuleAsync() => RunAsync(async ct =>
    {
        RequireStopped();
        if (!int.TryParse(RulePriority, out var priority)) throw new EditorValidationException("Приоритет должен быть целым числом.");
        if (string.IsNullOrWhiteSpace(RuleName) || string.IsNullOrWhiteSpace(RuleValue))
            throw new EditorValidationException("Назовите правило и укажите приложение. Его можно выбрать во вкладке «Процессы».");
        if (RuleSelector == SelectorKind.ProcessInstance && (!ExperimentalProcessTrees || SelectedRule?.Selector.Instance is null))
            throw new EditorValidationException("Сначала сохраните настройку backend дерева PID и создайте правило из списка процессов.");
        if (RuleAction == RouteAction.Proxy && RuleProfile is null) throw new EditorValidationException("Выберите прокси-профиль.");
        var r = new RoutingRule
        {
            Id = SelectedRule?.Id ?? Guid.NewGuid(), Name = RuleName.Trim(), Enabled = RuleEnabled, Priority = priority,
            Selector = new(RuleSelector, RuleValue.Trim(), RuleSelector == SelectorKind.ProcessInstance ? SelectedRule?.Selector.Instance : null), Network = RuleNetwork, Action = RuleAction,
            IncludeChildren = RuleIncludeChildren,
            ProfileId = RuleAction == RouteAction.Proxy ? RuleProfile?.Id : null, OnProxyFailure = FailurePolicy.Block
        };
        var next = _configuration with { Rules = _configuration.Rules.Where(x => x.Id != r.Id).Append(r).ToList() };
        ValidateLocal(next);
        await PersistAsync(next, ct);
        SelectedRule = Rules.First(x => x.Id == r.Id);
        Notice = "Правило сохранено. Меньшее значение приоритета применяется раньше."; AddLog("Правило сохранено.");
    }, true);
    [RelayCommand] private Task DeleteRuleAsync() => RunAsync(async ct =>
    {
        RequireStopped(); var r = SelectedRule ?? throw new EditorValidationException("Выберите правило.");
        await PersistAsync(_configuration with { Rules = _configuration.Rules.Where(x => x.Id != r.Id).ToList() }, ct);
        SelectedRule = null; Notice = "Правило удалено.";
    }, true);
    [RelayCommand] private Task RefreshProcessesAsync() => RunAsync(RefreshProcessesCoreAsync);
    [RelayCommand] private Task CreateNameRulesAsync() => CreateProcessRulesAsync(SelectorKind.ProcessName);
    [RelayCommand] private Task CreatePathRulesAsync() => CreateProcessRulesAsync(SelectorKind.ExecutablePath);
    [RelayCommand] private Task CreatePidTreeRulesAsync() => RunAsync(async ct =>
    {
        RequireStopped();
        if (!_configuration.Settings.ExperimentalProcessTrees) throw new EditorValidationException("Сначала включите и сохраните экспериментальный backend дерева PID.");
        var selected = SelectedProcesses.ToArray();
        if (selected.Length == 0 || selected.Any(p => p.Pid <= 4 || p.StartTimeUtc is null || p.SequenceNumber is not > 0))
            throw new EditorValidationException("Выберите процессы с доступными PID, временем создания и системным номером экземпляра.");
        var profile = Profiles.FirstOrDefault(p => p.Enabled) ?? throw new EditorValidationException("Создайте включённый профиль.");
        var additions = selected.DistinctBy(p => new { p.Pid, p.StartTimeUtc }).Select(p => new RoutingRule {
            Name = $"{p.Name} — дерево PID {p.Pid}", Selector = new(SelectorKind.ProcessInstance, p.Pid.ToString(System.Globalization.CultureInfo.InvariantCulture), new(p.Pid,p.StartTimeUtc!.Value,p.SequenceNumber)),
            IncludeChildren = true, ProfileId = profile.Id, Network = NetworkTransport.Tcp }).ToList();
        var next = _configuration with { Rules = _configuration.Rules.Concat(additions).ToList() };
        ValidateLocal(next); await PersistAsync(next,ct);
        SelectedRule = Rules.First(r => r.Id == additions[0].Id); SelectedTab = 2;
        Notice = "Созданы TCP-правила точного дерева PID. После перезапуска корневого приложения выберите его новый экземпляр. Требуется отдельная экспериментальная сборка движка.";
    },true);
    private Task CreateProcessRulesAsync(SelectorKind kind) => RunAsync(async ct =>
    {
        RequireStopped(); var selected = SelectedProcesses.ToArray();
        if (selected.Length == 0) throw new EditorValidationException("Выберите один или несколько процессов.");
        if (kind == SelectorKind.ExecutablePath && selected.Any(p => p.ExecutablePath is null))
            throw new EditorValidationException("Путь части выбранных процессов недоступен. Используйте правило по имени или измените выбор.");
        var profile = Profiles.FirstOrDefault(p => p.Enabled) ?? throw new EditorValidationException("Сначала создайте и включите прокси-профиль.");
        var values = selected.Select(p => kind == SelectorKind.ProcessName ? p.Name : p.ExecutablePath!).Distinct(StringComparer.OrdinalIgnoreCase);
        var additions = values.Select(v => new RoutingRule
        { Name = System.IO.Path.GetFileName(v), Selector = new(kind, v), ProfileId = profile.Id, Network = NetworkTransport.Tcp, Priority = 100 }).ToList();
        var next = _configuration with { Rules = _configuration.Rules.Concat(additions).ToList() };
        ValidateLocal(next); await PersistAsync(next, ct);
        SelectedRule = Rules.First(r => r.Id == additions[0].Id); SelectedTab = 2;
        Notice = $"Создано правил: {additions.Count}. TCP, профиль «{profile.Name}». Проверьте параметры перед запуском.";
    }, true);
    [RelayCommand] private Task ValidateAsync() => RunAsync(async ct =>
    {
        var validation = await engine.ValidateAsync(_configuration, ct);
        ValidationText = validation.Issues.Count == 0 ? "Конфигурация проверена. Фактическая маршрутизация требует проверки на Windows."
            : string.Join("\n", validation.Issues.Select(i => $"{(i.IsWarning ? "Предупреждение" : "Ошибка")}: {i.Message}"));
        Notice = validation.IsValid ? "Валидация пройдена." : "Исправьте ошибки конфигурации перед запуском.";
        AddLog(validation.IsValid ? "Валидация пройдена." : "Валидация обнаружила ошибки.");
    });
    [RelayCommand] private Task StartAsync() => RunAsync(async ct =>
    {
        RequireStopped(); var validation = await engine.ValidateAsync(_configuration, ct);
        ValidationText = string.Join("\n", validation.Issues.Select(i => i.Message));
        if (!validation.IsValid) throw new EditorValidationException("Конфигурация не прошла проверку. Подробности в разделе «Обзор».");
        StatusText = "Запуск…"; await engine.StartAsync(_configuration, ct); await UpdateStatusAsync(ct);
        Notice = "Запрос запуска выполнен. Проверьте фактический маршрут приложения; состояние процесса движка этого не доказывает.";
        AddLog("Запрос запуска выполнен.");
    }, true);
    [RelayCommand] private Task StopAsync() => RunAsync(async ct =>
    {
        await engine.StopAsync(ct); await UpdateStatusAsync(ct); Notice = StatusDetail; AddLog(StatusDetail);
    });
    [RelayCommand] private Task TestTcpAsync() => RunAsync(async ct =>
    {
        var p = DiagnosticProfile ?? throw new EditorValidationException("Выберите профиль для диагностики.");
        if (string.IsNullOrWhiteSpace(TargetHost) || !int.TryParse(TargetPort, out var port) || port is < 1 or > 65535)
            throw new EditorValidationException("Укажите адрес цели и порт от 1 до 65535.");
        var r = await diagnostics.TestTcpAsync(p, TargetHost.Trim(), port, ct);
        DiagnosticText = $"TCP · {DateTime.Now:HH:mm:ss}\n{r.Stage}: {r.Message}\nUDP: {r.Udp}. TUN и маршрутизация процесса этим тестом не проверяются.";
        AddLog(r.Success ? "TCP-диагностика завершилась успешно." : "TCP-диагностика обнаружила ошибку.");
    });
    [RelayCommand] private Task TestUdpAsync() => RunAsync(async ct =>
    {
        var p = DiagnosticProfile ?? throw new EditorValidationException("Выберите профиль для диагностики.");
        var r = diagnostics is IUdpConnectivityDiagnostics connectivity ? await connectivity.TestUdpConnectivityAsync(p, ct)
            : await diagnostics.TestUdpAssociateAsync(p, ct);
        DiagnosticText = $"UDP · {DateTime.Now:HH:mm:ss}\n{r.Stage}: {r.Message}\nТест не включает UDP в правилах и не меняет системный DNS.";
        AddLog(r.Success ? "UDP-проверка завершена. Маршрут приложения проверяется отдельно." : "UDP-проверка не пройдена. Подробности в диагностике.");
    });
    [RelayCommand] private Task TestUdpEchoAsync() => RunAsync(async ct =>
    {
        RequireStopped();
        if (diagnostics is not IUdpRelayDiagnostics relay)
            throw new EditorValidationException("Этот диагностический адаптер не поддерживает UDP echo.");
        var profile = DiagnosticProfile ?? throw new EditorValidationException("Выберите профиль для UDP echo.");
        if (!UdpVerificationPolicy.IsProbeTarget(UdpEchoHost.Trim(), out var target)
            || !int.TryParse(UdpEchoPort, out var port) || port is < 1 or > 65535)
            throw new EditorValidationException("Укажите буквальный IP контролируемого вами UDP echo-сервера и порт от 1 до 65535. DNS-имя не допускается.");
        var fingerprint = UdpVerificationPolicy.Fingerprint(profile);
        var result = await relay.TestUdpRelayAsync(profile, new(target.ToString(), port), ct);
        var current = _configuration.Profiles.FirstOrDefault(p => p.Id == profile.Id);
        if (current is null || UdpVerificationPolicy.Fingerprint(current) != fingerprint
            || result.Evidence.ProfileFingerprint != fingerprint)
            throw new EditorValidationException("Профиль изменился во время проверки. Результат не сохранён; повторите UDP echo.");
        if (!UdpVerificationPolicy.IsProbeTarget(result.Evidence.TargetHost, out var evidenceTarget) || !evidenceTarget.Equals(target)
            || result.Evidence.TargetPort != port)
            throw new EditorValidationException("Диагностический адаптер вернул результат для другой цели. Проверка не сохранена.");
        var details = DescribeProbe(result);
        DiagnosticText = details + "\nРезультат получен; сохранение…";
        var next = _configuration with
        { Profiles = _configuration.Profiles.Select(p => p.Id == profile.Id ? p with { UdpVerification = result.Evidence } : p).ToList() };
        try { await PersistAsync(next, ct); }
        catch { DiagnosticText = details + "\nНе удалось сохранить результат. Исторический статус профиля не изменён."; throw; }
        DiagnosticText = details + "\nРезультат сохранён локально. Echo не включает UDP в правилах автоматически.";
        Notice = result.Success ? "UDP echo завершён. Подтверждён только relay к указанной цели; TUN и Discord voice не проверены."
            : "UDP echo не подтвердил передачу. Результат диагностики сохранён; скрытого Direct fallback нет.";
        AddLog(result.Success ? "UDP echo: результат сохранён; TUN и Discord voice не проверены."
            : "UDP echo: передача не подтверждена; результат сохранён.");
    }, true);
    [RelayCommand] private Task InstallEngineAsync() => RunAsync(async ct =>
    {
        RequireStopped();
        if (engineInstaller is null) throw new EditorValidationException("В этой сборке установка движка недоступна.");
        Notice = "Установка и проверка движка PathFlux…";
        EngineInstallation installed;
        try { installed = await engineInstaller.InstallAsync(ct); }
        catch (InvalidOperationException ex) { throw new EditorValidationException(ex.Message); }
        var settings = _configuration.Settings with { EnginePath = installed.Path, EngineSha256 = installed.Sha256 };
        await PersistAsync(_configuration with { Settings = settings }, ct);
        EnginePath = installed.Path; EngineSha256 = installed.Sha256;
        Notice = "Движок установлен. Путь и SHA-256 заполнены и сохранены. Для обычных правил режим дерева PID включать не нужно.";
        AddLog("Проверенный движок PathFlux установлен; настройки сохранены.");
    }, true);

    [RelayCommand] private Task SaveSettingsAsync() => RunAsync(async ct =>
    {
        RequireStopped();
        if (!int.TryParse(RefreshSeconds, out var interval) || interval is < 2 or > 300)
            throw new EditorValidationException("Интервал обновления должен быть от 2 до 300 секунд.");
        var settings = _configuration.Settings with
        { EnginePath = EnginePath.Trim(), EngineSha256 = EngineSha256.Trim(), Theme = SelectedTheme, BypassLan = BypassLan, ProcessRefreshSeconds = interval, ExperimentalSocksUdp = ExperimentalSocksUdp, ExperimentalProcessTrees = ExperimentalProcessTrees };
        await PersistAsync(_configuration with { Settings = settings }, ct); ThemeChanged?.Invoke(SelectedTheme);
        Notice = "Настройки сохранены. Для запуска укажите доверенный sing-box и его SHA-256.";
    }, true);

    private static void ValidateLocal(ProxyConfiguration config)
    {
        var validation = ConfigurationValidator.Validate(config);
        if (!validation.IsValid) throw new EditorValidationException(string.Join("\n", validation.Issues.Where(i => !i.IsWarning).Select(i => i.Message)));
    }
    private static string CapabilityLabel(SupportStatus status) => status switch
    {
        SupportStatus.Implemented => "доступно", SupportStatus.Partial => "с ограничениями",
        SupportStatus.Experimental => "требуется проверка совместимости", SupportStatus.Unsupported => "недоступно",
        SupportStatus.Failed => "ошибка", _ => "не проверено"
    };
    private async Task PersistAsync(ProxyConfiguration next, CancellationToken ct)
    { ValidateLocal(next); await store.SaveAsync(next, ct); _configuration = next; LoadCollections(); }
    private void LoadCollections()
    {
        var profileId = SelectedProfile?.Id; var diagnosticId = DiagnosticProfile?.Id;
        var ruleProfileId = RuleProfile?.Id; var ruleId = SelectedRule?.Id;
        Profiles.Clear(); foreach (var p in _configuration.Profiles.OrderBy(p => p.Name)) Profiles.Add(p);
        Rules.Clear(); foreach (var r in _configuration.Rules.OrderBy(r => r.Priority).ThenBy(r => r.Id)) Rules.Add(r);
        SelectedProfile = Profiles.FirstOrDefault(p => p.Id == profileId);
        DiagnosticProfile = Profiles.FirstOrDefault(p => p.Id == diagnosticId) ?? Profiles.FirstOrDefault();
        RuleProfile = Profiles.FirstOrDefault(p => p.Id == ruleProfileId) ?? Profiles.FirstOrDefault();
        SelectedRule = Rules.FirstOrDefault(r => r.Id == ruleId);
        OnPropertyChanged(nameof(ProfileCount)); OnPropertyChanged(nameof(RuleCount));
    }
    private async Task RefreshProcessesCoreAsync(CancellationToken ct)
    { _processSnapshot = await discovery.GetProcessesAsync(ct); FilterProcesses(); }
    private void FilterProcesses()
    {
        var q = ProcessSearch.Trim();
        var matching = _processSnapshot.Where(p => q.Length == 0 || p.Name.Contains(q, StringComparison.OrdinalIgnoreCase)
            || p.Pid.ToString().Contains(q, StringComparison.OrdinalIgnoreCase) || p.PathDisplay.Contains(q, StringComparison.OrdinalIgnoreCase));
        matching = ProcessSort switch { "PID" => matching.OrderBy(p => p.Pid), "Путь" => matching.OrderBy(p => p.PathDisplay), _ => matching.OrderBy(p => p.Name).ThenBy(p => p.Pid) };
        var selected = SelectedProcesses.Select(p => (p.Pid, p.StartTimeUtc)).ToHashSet();
        Processes.Clear(); SelectedProcesses.Clear();
        foreach (var p in matching) { Processes.Add(p); if (selected.Contains((p.Pid, p.StartTimeUtc))) SelectedProcesses.Add(p); }
        ProcessSummary = $"Показано {Processes.Count} из {_processSnapshot.Count} · {DateTime.Now:HH:mm:ss}. Фактическая маршрутизация не измеряется.";
    }
    private async Task PollAsync(CancellationToken ct)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(2)); var lastRefresh = DateTimeOffset.UtcNow;
        try
        {
            while (await timer.WaitForNextTickAsync(ct))
            {
                if (IsBusy) continue;
                await UpdateStatusAsync(ct);
                if ((DateTimeOffset.UtcNow - lastRefresh).TotalSeconds >= _configuration.Settings.ProcessRefreshSeconds)
                { await RefreshProcessesCoreAsync(ct); lastRefresh = DateTimeOffset.UtcNow; }
            }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { }
        catch (Exception ex) { AddLog($"Фоновое обновление остановлено ({ex.GetType().Name}). Используйте ручное обновление."); }
    }
    private async Task UpdateStatusAsync(CancellationToken ct)
    {
        var s = await engine.GetStatusAsync(ct); _state = s.State;
        StatusText = s.State switch { EngineState.Stopped => "Остановлен", EngineState.Starting => "Запуск", EngineState.Running => "Движок запущен",
            EngineState.Degraded => "Ограниченный режим", EngineState.Stopping => "Остановка", _ => "Ошибка движка" };
        StatusDetail = s.Message + (s.ProcessId is { } pid ? $" · PID {pid}" : ""); NotifyPermissions();
        var stats = s.Udp ?? [];
        LiveUdpText = stats.Count == 0 ? "UDP-посредники не запущены. Включение — вручную в настройках; нужен SOCKS5 и UDP-правило." :
            string.Join("\n\n", stats.Select(u => $"Профиль {Profiles.FirstOrDefault(p => p.Id == u.ProfileId)?.Name ?? u.ProfileId.ToString()}: {BridgeStateLabel(u.State)}\nАктивных ассоциаций: {u.ActiveAssociations} · отправлено: {u.SentPackets} · получено: {u.ReceivedPackets}\nПереподключений: {u.Reconnects} · FRAG отклонено: {u.DroppedFragments} · некорректных: {u.DroppedInvalid}\nПоследняя ошибка: {u.LastError ?? "нет"}"));
        if (IsRecordingUdp)
        {
            try
            {
                await System.IO.File.AppendAllTextAsync(UdpRecordingPath, System.Text.Json.JsonSerializer.Serialize(new
                { SchemaVersion = 1, TimestampUtc = DateTimeOffset.UtcNow, EngineState = s.State.ToString(), EngineProcessId = s.ProcessId, Udp = stats }) + "\n", ct);
                if (++_udpRecordedSamples >= 7200) IsRecordingUdp = false;
            }
            catch (Exception ex) when (ex is System.IO.IOException or UnauthorizedAccessException)
            { IsRecordingUdp = false; AddLog("Не удалось записать UDP-метрики. Сбор остановлен."); }
        }
    }
    private static string BridgeStateLabel(string state) => state switch
    {
        "Listening" => "Ожидает соединений", "Active" => "Активен", "Waiting / Reconnecting" => "Ожидание / переподключение",
        "Failed" => "Ошибка; UDP заблокирован", "Stopped" => "Остановлен", _ => "Неизвестно"
    };
    [RelayCommand] private async Task ToggleUdpRecordingAsync()
    {
        if (IsRecordingUdp) { IsRecordingUdp = false; Notice = "Сбор UDP-метрик остановлен: " + UdpRecordingPath; return; }
        try
        {
            string directory = System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "PathFlux", "diagnostics");
            System.IO.Directory.CreateDirectory(directory);
            UdpRecordingPath = System.IO.Path.Combine(directory, "udp-" + DateTimeOffset.UtcNow.ToString("yyyyMMdd-HHmmss") + "-" + Guid.NewGuid().ToString("N") + ".jsonl");
            await System.IO.File.WriteAllTextAsync(UdpRecordingPath, "");
            _udpRecordedSamples = 0; IsRecordingUdp = true;
            Notice = "Сбор UDP-метрик включён (до 4 часов). Пакеты и credentials не записываются.";
        }
        catch (Exception ex) when (ex is System.IO.IOException or UnauthorizedAccessException) { Notice = "Не удалось создать файл UDP-метрик."; }
    }
    private void NotifyPermissions()
    {
        OnPropertyChanged(nameof(EngineActive)); OnPropertyChanged(nameof(CanEdit)); OnPropertyChanged(nameof(CanStart));
        OnPropertyChanged(nameof(CanStop)); OnPropertyChanged(nameof(CanUseTools)); OnPropertyChanged(nameof(EditingHint));
        OnPropertyChanged(nameof(ProfileUdpStatus)); OnPropertyChanged(nameof(DiagnosticUdpStatus));
    }
    private bool ProfileEditorIdentityMatches(ProxyProfile profile)
    {
        if (ReplaceCredentials || RemoveCredentials && profile.CredentialsRef is not null
            || !int.TryParse(ProfilePort, out var port)) return false;
        var edited = profile with
        {
            Protocol = ProfileProtocol, Host = ProfileHost.Trim(), Port = port,
            TlsServerName = IsHttps && !string.IsNullOrWhiteSpace(ProfileTlsServerName) ? ProfileTlsServerName.Trim() : null,
            UdpRelayMode = IsSocks ? ProfileUdpRelayMode : UdpRelayMode.Standard,
            UdpPublishedPortFirst = IsDockerNat && int.TryParse(ProfileUdpPortFirst, out int begin) ? begin : null,
            UdpPublishedPortLast = IsDockerNat && int.TryParse(ProfileUdpPortLast, out int end) ? end : null
        };
        return UdpVerificationPolicy.Fingerprint(profile) == UdpVerificationPolicy.Fingerprint(edited);
    }
    private static string DescribeUdp(ProxyProfile profile)
    {
        var now = DateTimeOffset.UtcNow;
        var description = UdpVerificationPolicy.Describe(profile, now);
        return description + (UdpVerificationPolicy.IsCurrent(profile, now)
            && profile.UdpVerification is { } evidence && evidence.CheckedAtUtc <= DateTimeOffset.MaxValue - UdpVerificationPolicy.Validity
            ? $"\nСрок актуальности — 15 минут, до {(evidence.CheckedAtUtc + UdpVerificationPolicy.Validity).ToLocalTime():dd.MM.yyyy HH:mm:ss}."
            : "\nПоложительный результат актуален 15 минут. UDP-маршрутизация TUN остаётся неподтверждённой.");
    }
    private static string DescribeProbe(UdpRelayProbeResult result)
    {
        var e = result.Evidence;
        var latency = e.AverageRoundTripMs is { } ms ? $"{ms:F1} мс" : "нет подтверждённых ответов";
        return $"UDP echo · {e.CheckedAtUtc.ToLocalTime():dd.MM.yyyy HH:mm:ss}\nЭтап: {result.Stage} · {result.Message}"
            + $"\nСтатус relay: {e.Status}\nОтправлено: {e.SentPackets}; получено точных ответов: {e.ReceivedPackets}. Средний RTT: {latency}."
            + "\nПроверяется только relay к выбранному echo-серверу. TUN, DNS и Discord voice не проверены.";
    }
    private void RequireStopped()
    { if (EngineActive) throw new EditorValidationException("Сначала остановите движок: применение изменений во время работы пока недоступно."); }
    private async Task RunAsync(Func<CancellationToken, Task> action, bool requireEditable = false)
    {
        if (IsBusy || _disposed) return;
        if (requireEditable && !CanEdit) { Notice = EditingHint; return; }
        IsBusy = true;
        _operationFinished = new(TaskCreationOptions.RunContinuationsAsynchronously);
        try { await action(_lifetime.Token); }
        catch (EditorValidationException ex) { Notice = ex.Message; }
        catch (EngineOperationException ex)
        {
            Notice = ex.Message;
            AddLog(ex.Message);
            try { await UpdateStatusAsync(_lifetime.Token); } catch { }
        }
        catch (OperationCanceledException) when (_lifetime.IsCancellationRequested) { }
        catch (Exception ex)
        {
            // Never log protocol exception messages: upstream responses may contain credentials.
            Notice = $"Операция не выполнена ({ex.GetType().Name}). Проверьте настройки и доступ к файлам; секреты в журнал не записываются.";
            AddLog($"Ошибка операции: {ex.GetType().Name}."); try { await UpdateStatusAsync(_lifetime.Token); } catch { }
        }
        finally { IsBusy = false; _operationFinished.TrySetResult(); }
    }
    private void ClearCredentialEditor()
    { ProfileUsername = ""; ProfilePassword = ""; ReplaceCredentials = false; RemoveCredentials = false; }
    private async Task DeleteIfUnusedAsync(string reference, CancellationToken ct)
    {
        if (_configuration.Profiles.All(p => p.CredentialsRef != reference)
            && store is ISecretReferenceRetention retention && !await retention.IsReferencedAsync(reference, ct))
            await TryDeleteSecretAsync(reference, ct);
    }
    private async Task TryDeleteSecretAsync(string reference, CancellationToken ct)
    {
        try { await secrets.DeleteAsync(reference, ct); }
        catch (Exception ex) when (ex is not OperationCanceledException) { AddLog($"Не удалось удалить неиспользуемый секрет ({ex.GetType().Name})."); }
    }
    private void AddLog(string message)
    { LogEntries.Insert(0, $"{DateTime.Now:HH:mm:ss} · {message}"); while (LogEntries.Count > 150) LogEntries.RemoveAt(LogEntries.Count - 1); }
    // Exit is allowed only after the adapter confirms that its owned resources are stopped.
    // A failed attempt leaves polling and commands alive so recovery can be retried.
    public async Task<bool> TryStopForExitAsync()
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var ownsBusyState = false;
        try
        {
            if (_operationFinished is { } operation) await operation.Task.WaitAsync(timeout.Token);
            IsBusy = true;
            ownsBusyState = true;
            await engine.StopAsync(timeout.Token);
            await UpdateStatusAsync(timeout.Token);
            if (!EngineActive) return true;
            Notice = "Выход отложен: остановка движка или очистка сети не подтверждена. " + StatusDetail;
        }
        catch (Exception ex)
        {
            Notice = $"Выход отложен: остановка не подтверждена ({ex.GetType().Name}). Повторите остановку движка.";
        }
        finally { if (ownsBusyState) IsBusy = false; }
        AddLog(Notice);
        return false;
    }

    public async ValueTask DisposeAsync()
    {
        if (_disposed) return; _disposed = true; await _lifetime.CancelAsync();
        if (_operationFinished is { } operation) await operation.Task;
        if (_pollTask is not null) await _pollTask;
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        try { await engine.StopAsync(timeout.Token); } catch { /* Agent owns cleanup on lost UI connection. */ }
        _lifetime.Dispose(); ClearCredentialEditor();
    }
    private sealed class EditorValidationException(string message) : Exception(message);
}
