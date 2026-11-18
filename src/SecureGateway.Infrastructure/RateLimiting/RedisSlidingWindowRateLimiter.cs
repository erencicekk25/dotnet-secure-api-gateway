using SecureGateway.Application.RateLimiting;
using StackExchange.Redis;

namespace SecureGateway.Infrastructure.RateLimiting;

/// <summary>
/// Distributed <b>sliding window log</b> rate limiter backed by Redis sorted sets.
/// </summary>
/// <remarks>
/// <para>
/// Every admitted request is stored as a member of a sorted set scored by its arrival time in
/// milliseconds. On each evaluation, entries older than the window are trimmed and the remaining
/// cardinality is compared with the limit. Unlike fixed windows, this produces no burst at window
/// boundaries: at any instant, at most <c>PermitLimit</c> requests exist in the last <c>Window</c>.
/// </para>
/// <para>
/// The whole check-and-increment runs inside one Lua script, which Redis executes atomically. That
/// gives three guarantees: (1) no race between concurrent gateway replicas, (2) multiple quotas
/// for one request are all-or-nothing, and (3) a single network round-trip per request.
/// </para>
/// <para>
/// Time is taken from the Redis server (<c>TIME</c>), not from the gateway hosts, so clock skew
/// between replicas cannot inflate or shrink a caller's quota.
/// </para>
/// </remarks>
public sealed class RedisSlidingWindowRateLimiter(IConnectionMultiplexer redis) : IRateLimiter
{
    // ARGV[1]          = unique member id for this request
    // ARGV[2i], [2i+1] = window (ms) and permit limit for KEYS[i]
    // Returns {allowed (0|1), index of decisive key (1-based), remaining, retryAfterMs}
    internal const string SlidingWindowScript = """
        local time = redis.call('TIME')
        local now = tonumber(time[1]) * 1000 + math.floor(tonumber(time[2]) / 1000)
        local member = ARGV[1]
        local counts = {}

        for i = 1, #KEYS do
          local window = tonumber(ARGV[i * 2])
          local limit = tonumber(ARGV[i * 2 + 1])
          redis.call('ZREMRANGEBYSCORE', KEYS[i], '-inf', now - window)
          local count = redis.call('ZCARD', KEYS[i])
          if count >= limit then
            local retry = window
            local oldest = redis.call('ZRANGE', KEYS[i], 0, 0, 'WITHSCORES')
            if oldest[2] then
              retry = tonumber(oldest[2]) + window - now
            end
            if retry < 1 then retry = 1 end
            return {0, i, 0, retry}
          end
          counts[i] = count
        end

        local decisive = 1
        local minRemaining = -1
        for i = 1, #KEYS do
          local window = tonumber(ARGV[i * 2])
          local limit = tonumber(ARGV[i * 2 + 1])
          redis.call('ZADD', KEYS[i], now, member)
          redis.call('PEXPIRE', KEYS[i], window)
          local remaining = limit - counts[i] - 1
          if minRemaining < 0 or remaining < minRemaining then
            minRemaining = remaining
            decisive = i
          end
        end

        return {1, decisive, minRemaining, 0}
        """;

    public async ValueTask<RateLimitDecision> TryAcquireAsync(
        IReadOnlyList<RateLimitRule> rules,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(rules);
        if (rules.Count == 0)
        {
            throw new ArgumentException("At least one rate limit rule is required.", nameof(rules));
        }

        cancellationToken.ThrowIfCancellationRequested();

        var keys = new RedisKey[rules.Count];
        var args = new RedisValue[1 + (rules.Count * 2)];
        args[0] = Guid.NewGuid().ToString("N");

        for (var i = 0; i < rules.Count; i++)
        {
            keys[i] = rules[i].Key;
            args[1 + (i * 2)] = (long)rules[i].Policy.Window.TotalMilliseconds;
            args[2 + (i * 2)] = rules[i].Policy.PermitLimit;
        }

        RedisResult raw;
        try
        {
            // StackExchange.Redis caches the script SHA and transparently uses EVALSHA.
            raw = await redis.GetDatabase().ScriptEvaluateAsync(SlidingWindowScript, keys, args).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is RedisException or TimeoutException or ObjectDisposedException)
        {
            throw new RateLimiterUnavailableException("The distributed rate limiter store is unavailable.", ex);
        }

        var result = (RedisResult[])raw!;
        var allowed = (long)result[0] == 1;
        var decisiveIndex = (int)(long)result[1] - 1;
        var remaining = (int)(long)result[2];
        var retryAfter = TimeSpan.FromMilliseconds((long)result[3]);

        return new RateLimitDecision(allowed, rules[decisiveIndex].Policy, Math.Max(0, remaining), retryAfter);
    }
}
