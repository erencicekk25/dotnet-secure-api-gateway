namespace SecureGateway.Domain.Security;

/// <summary>
/// An immutable audit record describing a security-relevant incident observed at the gateway edge
/// (quota violations, rejected credentials, access-control denials, degraded protection, ...).
/// </summary>
public sealed record SecurityEvent
{
    public Guid Id { get; init; } = Guid.NewGuid();

    public DateTimeOffset OccurredAtUtc { get; init; } = DateTimeOffset.UtcNow;

    public required SecurityEventType EventType { get; init; }

    public required SecuritySeverity Severity { get; init; }

    /// <summary>End-to-end trace identifier shared with every downstream service log.</summary>
    public required string CorrelationId { get; init; }

    public string? ClientIp { get; init; }

    public string? UserId { get; init; }

    public string? HttpMethod { get; init; }

    public string? Path { get; init; }

    public string? RouteId { get; init; }

    public int? StatusCode { get; init; }

    /// <summary>Free-form, non-sensitive diagnostic detail (never tokens, secrets or payloads).</summary>
    public string? Details { get; init; }
}
