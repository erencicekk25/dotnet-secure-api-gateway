using SecureGateway.Domain.Security;

namespace SecureGateway.Application.Security;

/// <summary>Durable storage for the security audit trail.</summary>
public interface ISecurityEventStore
{
    /// <summary>Creates the schema if it does not exist. Must be idempotent.</summary>
    Task InitializeAsync(CancellationToken cancellationToken);

    Task WriteBatchAsync(IReadOnlyCollection<SecurityEvent> events, CancellationToken cancellationToken);

    Task<IReadOnlyList<SecurityEvent>> QueryRecentAsync(
        int take,
        SecurityEventType? eventType,
        CancellationToken cancellationToken);
}
