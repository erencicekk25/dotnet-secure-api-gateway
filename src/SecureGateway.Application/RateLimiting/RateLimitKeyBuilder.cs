using System.Security.Cryptography;
using System.Text;

namespace SecureGateway.Application.RateLimiting;

/// <summary>
/// Builds deterministic Redis keys for quota counters.
/// </summary>
/// <remarks>
/// Key layout: <c>{prefix}:{{routeId}}:{policy}:{strategy}:{partition}</c>.
/// The route id is wrapped in a Redis Cluster <i>hash tag</i>, so every counter that belongs to the same
/// route lands on the same slot. This allows multiple quotas of one route to be evaluated in a single
/// atomic Lua script without CROSSSLOT errors, while different routes are still spread across shards.
/// </remarks>
public static class RateLimitKeyBuilder
{
    /// <summary>Partition values longer than this are hashed to keep keys compact and bounded.</summary>
    public const int MaxPartitionLength = 128;

    public static string Build(
        string prefix,
        string routeId,
        string policyName,
        PartitionStrategy strategy,
        string partitionValue)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(prefix);
        ArgumentException.ThrowIfNullOrWhiteSpace(routeId);
        ArgumentException.ThrowIfNullOrWhiteSpace(policyName);
        ArgumentException.ThrowIfNullOrWhiteSpace(partitionValue);

        var partition = partitionValue.Length > MaxPartitionLength
            ? "sha256-" + Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(partitionValue)))
            : partitionValue;

        return $"{prefix}:{{{Sanitize(routeId)}}}:{policyName.ToLowerInvariant()}:{StrategySegment(strategy)}:{partition}";
    }

    private static string StrategySegment(PartitionStrategy strategy) => strategy switch
    {
        PartitionStrategy.ClientIp => "ip",
        PartitionStrategy.User => "user",
        PartitionStrategy.Endpoint => "endpoint",
        _ => throw new ArgumentOutOfRangeException(nameof(strategy), strategy, "Unsupported partition strategy.")
    };

    // Braces inside the route id would break the hash tag semantics.
    private static string Sanitize(string value) => value.Replace('{', '_').Replace('}', '_');
}
