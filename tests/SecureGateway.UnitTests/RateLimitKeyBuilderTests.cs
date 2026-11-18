using SecureGateway.Application.RateLimiting;

namespace SecureGateway.UnitTests;

public sealed class RateLimitKeyBuilderTests
{
    [Fact]
    public void Build_WrapsRouteIdInRedisClusterHashTag()
    {
        var key = RateLimitKeyBuilder.Build("gw:rl", "payments-route", "Payments-Per-User", PartitionStrategy.User, "customer-42");

        Assert.Equal("gw:rl:{payments-route}:payments-per-user:user:customer-42", key);
    }

    [Fact]
    public void Build_KeysForSameRouteShareTheSameHashTag()
    {
        var userKey = RateLimitKeyBuilder.Build("gw:rl", "payments-route", "a", PartitionStrategy.User, "u1");
        var endpointKey = RateLimitKeyBuilder.Build("gw:rl", "payments-route", "b", PartitionStrategy.Endpoint, "all");

        Assert.Equal(ExtractHashTag(userKey), ExtractHashTag(endpointKey));
    }

    [Fact]
    public void Build_HashesOversizedPartitionValues()
    {
        var huge = new string('x', RateLimitKeyBuilder.MaxPartitionLength + 1);

        var key = RateLimitKeyBuilder.Build("gw:rl", "r", "p", PartitionStrategy.User, huge);

        Assert.Contains(":sha256-", key);
        Assert.DoesNotContain(huge, key);
    }

    [Fact]
    public void Build_NeutralizesBracesInRouteId()
    {
        var key = RateLimitKeyBuilder.Build("gw:rl", "/api/{id}", "p", PartitionStrategy.ClientIp, "10.0.0.1");

        Assert.Equal("{/api/_id_}", ExtractHashTag(key));
    }

    private static string ExtractHashTag(string key)
    {
        var start = key.IndexOf('{');
        var end = key.IndexOf('}', start);
        return key[start..(end + 1)];
    }
}
