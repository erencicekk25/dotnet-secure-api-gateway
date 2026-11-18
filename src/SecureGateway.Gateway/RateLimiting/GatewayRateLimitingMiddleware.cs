using System.Globalization;
using Microsoft.Extensions.Options;
using SecureGateway.Application.RateLimiting;
using SecureGateway.Application.Security;
using SecureGateway.Domain.Security;
using SecureGateway.Gateway.Extensions;
using SecureGateway.Gateway.Security;

namespace SecureGateway.Gateway.RateLimiting;

/// <summary>
/// Admission control for every request entering the gateway.
/// </summary>
/// <remarks>
/// Placed <b>after authentication</b> (so per-user quotas know the caller) but <b>before authorization</b>
/// (so anonymous floods and brute-force attempts are throttled before any policy evaluation or
/// downstream call happens).
/// </remarks>
public sealed partial class GatewayRateLimitingMiddleware(
    RequestDelegate next,
    IRateLimiter rateLimiter,
    IRateLimitPolicyResolver policyResolver,
    ISecurityEventPublisher securityEvents,
    IOptionsMonitor<RateLimitingOptions> optionsMonitor,
    ILogger<GatewayRateLimitingMiddleware> logger)
{
    public const string LimitHeader = "X-RateLimit-Limit";
    public const string RemainingHeader = "X-RateLimit-Remaining";
    public const string PolicyHeader = "X-RateLimit-Policy";

    /// <summary>During a Redis outage, emit at most one audit event per interval instead of one per request.</summary>
    private static readonly long OutageEventIntervalMs = (long)TimeSpan.FromSeconds(30).TotalMilliseconds;

    private long _lastOutageEventTick = long.MinValue / 2;

    public async Task InvokeAsync(HttpContext context)
    {
        var options = optionsMonitor.CurrentValue;
        var resolution = options.Enabled ? policyResolver.Resolve(context, options) : null;

        if (resolution is null)
        {
            await next(context);
            return;
        }

        var rules = BuildRules(context, options, resolution);

        RateLimitDecision decision;
        try
        {
            decision = await rateLimiter.TryAcquireAsync(rules, context.RequestAborted);
        }
        catch (RateLimiterUnavailableException ex)
        {
            await HandleLimiterOutageAsync(context, options, ex);
            return;
        }

        var response = context.Response;
        response.Headers[LimitHeader] = decision.Policy.PermitLimit.ToString(CultureInfo.InvariantCulture);
        response.Headers[RemainingHeader] = decision.Remaining.ToString(CultureInfo.InvariantCulture);
        response.Headers[PolicyHeader] = decision.Policy.Name;

        if (decision.IsAllowed)
        {
            await next(context);
            return;
        }

        await RejectAsync(context, resolution, decision);
    }

    internal static IReadOnlyList<RateLimitRule> BuildRules(
        HttpContext context,
        RateLimitingOptions options,
        RateLimitResolution resolution)
    {
        var rules = new RateLimitRule[resolution.Policies.Count];
        for (var i = 0; i < rules.Length; i++)
        {
            var policy = resolution.Policies[i];
            var partition = ResolvePartition(context, policy.PartitionBy);
            var key = RateLimitKeyBuilder.Build(options.KeyPrefix, resolution.RouteId, policy.Name, policy.PartitionBy, partition);
            rules[i] = new RateLimitRule(key, policy);
        }

        return rules;
    }

    internal static string ResolvePartition(HttpContext context, PartitionStrategy strategy) => strategy switch
    {
        PartitionStrategy.ClientIp => context.GetClientIp(),
        PartitionStrategy.User => context.GetUserId() ?? $"anonymous-{context.GetClientIp()}",
        PartitionStrategy.Endpoint => "all",
        _ => throw new ArgumentOutOfRangeException(nameof(strategy), strategy, "Unsupported partition strategy.")
    };

    private async Task RejectAsync(HttpContext context, RateLimitResolution resolution, RateLimitDecision decision)
    {
        var retryAfterSeconds = Math.Max(1, (int)Math.Ceiling(decision.RetryAfter.TotalSeconds));
        context.Response.Headers.RetryAfter = retryAfterSeconds.ToString(CultureInfo.InvariantCulture);

        LogQuotaExceeded(logger, decision.Policy.Name, resolution.RouteId, context.GetClientIp(), context.GetUserId());

        securityEvents.Publish(SecurityEventFactory.Create(
            context,
            SecurityEventType.RateLimitExceeded,
            decision.Policy.PartitionBy == PartitionStrategy.Endpoint ? SecuritySeverity.High : SecuritySeverity.Medium,
            StatusCodes.Status429TooManyRequests,
            $"policy={decision.Policy.Name}; partition={decision.Policy.PartitionBy}; limit={decision.Policy.PermitLimit}/{decision.Policy.WindowSeconds}s; retryAfter={retryAfterSeconds}s"));

        await GatewayProblemDetails.WriteAsync(
            context,
            StatusCodes.Status429TooManyRequests,
            "Too Many Requests",
            "The request quota for this resource has been exceeded. Retry after the indicated delay.",
            new Dictionary<string, object?>
            {
                ["policy"] = decision.Policy.Name,
                ["retryAfterSeconds"] = retryAfterSeconds
            });
    }

    private async Task HandleLimiterOutageAsync(HttpContext context, RateLimitingOptions options, RateLimiterUnavailableException exception)
    {
        LogLimiterUnavailable(logger, exception, options.FailOpen);

        var now = Environment.TickCount64;
        var last = Interlocked.Read(ref _lastOutageEventTick);
        if (now - last >= OutageEventIntervalMs
            && Interlocked.CompareExchange(ref _lastOutageEventTick, now, last) == last)
        {
            securityEvents.Publish(SecurityEventFactory.Create(
                context,
                SecurityEventType.RateLimiterUnavailable,
                SecuritySeverity.Critical,
                options.FailOpen ? null : StatusCodes.Status503ServiceUnavailable,
                $"Rate limiter backend unavailable; failOpen={options.FailOpen}; error={exception.InnerException?.GetType().Name}"));
        }

        if (options.FailOpen)
        {
            await next(context);
            return;
        }

        await GatewayProblemDetails.WriteAsync(
            context,
            StatusCodes.Status503ServiceUnavailable,
            "Service Unavailable",
            "Request admission control is temporarily unavailable. Please retry shortly.");
    }

    [LoggerMessage(EventId = 3001, Level = LogLevel.Warning,
        Message = "Rate limit policy {PolicyName} rejected request on route {RouteId} (ip={ClientIp}, user={UserId})")]
    private static partial void LogQuotaExceeded(ILogger logger, string policyName, string routeId, string clientIp, string? userId);

    [LoggerMessage(EventId = 3002, Level = LogLevel.Critical,
        Message = "Distributed rate limiter is unavailable; failOpen={FailOpen}")]
    private static partial void LogLimiterUnavailable(ILogger logger, Exception exception, bool failOpen);
}
