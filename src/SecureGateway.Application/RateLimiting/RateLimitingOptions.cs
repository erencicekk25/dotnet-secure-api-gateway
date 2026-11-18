namespace SecureGateway.Application.RateLimiting;

public sealed class RateLimitingOptions
{
    public const string SectionName = "RateLimiting";

    /// <summary>Global kill switch. Useful for incident response; should stay enabled in production.</summary>
    public bool Enabled { get; set; } = true;

    /// <summary>Namespace prefix for every Redis key written by the limiter.</summary>
    public string KeyPrefix { get; set; } = "gw:rl";

    /// <summary>Policy applied to endpoints that do not declare one explicitly (including unmatched paths).</summary>
    public string DefaultPolicy { get; set; } = "default";

    /// <summary>
    /// Behaviour when Redis is unreachable. <c>true</c> keeps traffic flowing (availability first);
    /// <c>false</c> rejects traffic with 503 (protection first). Choose per risk appetite.
    /// </summary>
    public bool FailOpen { get; set; } = true;

    public List<RateLimitPolicyOptions> Policies { get; set; } = [];

    public RateLimitPolicyOptions? FindPolicy(string name) =>
        Policies.Find(p => string.Equals(p.Name, name, StringComparison.OrdinalIgnoreCase));
}

public sealed class RateLimitPolicyOptions
{
    public string Name { get; set; } = string.Empty;

    public PartitionStrategy PartitionBy { get; set; } = PartitionStrategy.ClientIp;

    /// <summary>Maximum number of requests accepted inside any rolling window.</summary>
    public int PermitLimit { get; set; }

    /// <summary>Length of the rolling window in seconds.</summary>
    public int WindowSeconds { get; set; }

    public TimeSpan Window => TimeSpan.FromSeconds(WindowSeconds);
}
