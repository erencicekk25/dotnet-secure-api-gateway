using Microsoft.Extensions.Diagnostics.HealthChecks;
using StackExchange.Redis;

namespace SecureGateway.Infrastructure.HealthChecks;

public sealed class RedisHealthCheck(IConnectionMultiplexer redis) : IHealthCheck
{
    public async Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken cancellationToken = default)
    {
        try
        {
            var latency = await redis.GetDatabase().PingAsync().ConfigureAwait(false);
            return HealthCheckResult.Healthy($"Redis PING {latency.TotalMilliseconds:F1} ms");
        }
        catch (Exception ex)
        {
            return new HealthCheckResult(context.Registration.FailureStatus, "Redis is unreachable.", ex);
        }
    }
}
