namespace SecureGateway.Infrastructure.Security;

public sealed class SecurityAuditOptions
{
    public const string SectionName = "SecurityAudit";

    /// <summary>Bounded in-memory buffer between the request path and the database writer.</summary>
    public int ChannelCapacity { get; set; } = 10_000;

    /// <summary>Maximum number of events written in a single PostgreSQL COPY operation.</summary>
    public int BatchSize { get; set; } = 250;

    /// <summary>Maximum time an event waits in the buffer before being flushed.</summary>
    public int FlushIntervalMilliseconds { get; set; } = 1_000;

    /// <summary>Delay between attempts to initialize the schema while the database is starting up.</summary>
    public int InitializationRetrySeconds { get; set; } = 5;
}
