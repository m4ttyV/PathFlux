namespace PathFlux.Application;

/// <summary>Protects credentials required by persisted configurations and recovery copies.</summary>
public interface ISecretReferenceRetention
{
    /// <summary>Returns true if referenced, or if persisted data cannot safely be inspected.</summary>
    Task<bool> IsReferencedAsync(string reference, CancellationToken ct);
}
