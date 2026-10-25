using PathFlux.Domain;

namespace PathFlux.Application;

/// <summary>First match wins: ascending priority, then ordinal UUID, independent of input order.</summary>
public sealed class RuleCompiler(bool processTrees = false) : IRuleCompiler
{
    public Task<CompiledPolicy> CompileAsync(IReadOnlyList<RoutingRule> rules, IReadOnlyList<ProxyProfile> profiles, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        return Task.FromResult(Compile(rules, profiles));
    }

    public CompiledPolicy Compile(IReadOnlyList<RoutingRule> rules, IReadOnlyList<ProxyProfile> profiles)
    {
        var validation = ConfigurationValidator.ValidatePolicy(rules, profiles, processTrees);
        // Invalid tables are never partially usable: the engine must keep its previous working table.
        if (!validation.IsValid) return new([], [], validation.Issues);
        var compiledRules = rules.Where(rule => rule.Enabled)
            .OrderBy(rule => rule.Priority)
            .ThenBy(rule => rule.Id.ToString("D"), StringComparer.Ordinal).ToArray();
        var compiledProfiles = profiles.Where(profile => profile.Enabled)
            .OrderBy(profile => profile.Id.ToString("D"), StringComparer.Ordinal).ToArray();
        var issues = validation.Issues.ToList();
        for (var index = 0; index < compiledRules.Length; index++)
        {
            var later = compiledRules[index];
            if (compiledRules.Take(index).Any(earlier =>
                earlier.Selector.Kind == later.Selector.Kind &&
                string.Equals(earlier.Selector.Value, later.Selector.Value, StringComparison.OrdinalIgnoreCase) &&
                (earlier.Network == later.Network || earlier.Network == NetworkTransport.Both || later.Network == NetworkTransport.Both)))
                issues.Add(new("rule.overlap", "Предыдущее правило с тем же селектором имеет приоритет для совпавшего транспорта.", later.Id, true));
        }
        return new(compiledRules, compiledProfiles, issues);
    }
}
