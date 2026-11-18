namespace SecureGateway.Application.RateLimiting;

/// <summary>
/// A distributed limiter that evaluates one or more quotas for a single request <b>atomically</b>:
/// either every rule admits the request and all counters are incremented, or none of them are.
/// </summary>
public interface IRateLimiter
{
    /// <exception cref="RateLimiterUnavailableException">The backing store could not be reached.</exception>
    ValueTask<RateLimitDecision> TryAcquireAsync(IReadOnlyList<RateLimitRule> rules, CancellationToken cancellationToken);
}

/// <summary>A single quota to evaluate: a fully qualified counter key and the policy that governs it.</summary>
public sealed record RateLimitRule(string Key, RateLimitPolicyOptions Policy);

/// <summary>Outcome of a limiter evaluation.</summary>
/// <param name="IsAllowed">Whether the request may proceed.</param>
/// <param name="Policy">The policy that rejected the request, or the most constrained policy when allowed.</param>
/// <param name="Remaining">Permits left in the most constrained window.</param>
/// <param name="RetryAfter">How long the caller should wait before retrying (only meaningful when rejected).</param>
public readonly record struct RateLimitDecision(
    bool IsAllowed,
    RateLimitPolicyOptions Policy,
    int Remaining,
    TimeSpan RetryAfter);

public sealed class RateLimiterUnavailableException(string message, Exception innerException)
    : Exception(message, innerException);
