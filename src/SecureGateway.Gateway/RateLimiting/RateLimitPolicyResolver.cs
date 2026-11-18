using SecureGateway.Application.RateLimiting;
using SecureGateway.Gateway.Extensions;
using Yarp.ReverseProxy.Model;

namespace SecureGateway.Gateway.RateLimiting;

public sealed record RateLimitResolution(string RouteId, IReadOnlyList<RateLimitPolicyOptions> Policies);

public interface IRateLimitPolicyResolver
{
    /// <returns><c>null</c> when the endpoint is exempt from rate limiting.</returns>
    RateLimitResolution? Resolve(HttpContext context, RateLimitingOptions options);
}

/// <summary>
/// Determines which quota policies apply to the current request, based on endpoint metadata:
/// the <see cref="GatewayRateLimitAttribute"/> for local endpoints, the <c>RateLimitPolicies</c>
/// metadata entry for YARP routes, and the configured default policy otherwise.
/// </summary>
public sealed partial class RateLimitPolicyResolver(ILogger<RateLimitPolicyResolver> logger) : IRateLimitPolicyResolver
{
    public const string RouteMetadataKey = "RateLimitPolicies";

    public RateLimitResolution? Resolve(HttpContext context, RateLimitingOptions options)
    {
        var endpoint = context.GetEndpoint();
        if (endpoint?.Metadata.GetMetadata<DisableGatewayRateLimitAttribute>() is not null)
        {
            return null;
        }

        var routeId = context.GetGatewayRouteId();
        var declared = GetDeclaredPolicyNames(endpoint);
        var policies = new List<RateLimitPolicyOptions>(Math.Max(1, declared.Count));

        foreach (var name in declared)
        {
            var policy = options.FindPolicy(name);
            if (policy is null)
            {
                LogUnknownPolicy(logger, name, routeId);
                continue;
            }

            if (!policies.Contains(policy))
            {
                policies.Add(policy);
            }
        }

        if (policies.Count == 0)
        {
            // The options validator guarantees the default policy exists.
            policies.Add(options.FindPolicy(options.DefaultPolicy)!);
        }

        return new RateLimitResolution(routeId, policies);
    }

    private static IReadOnlyList<string> GetDeclaredPolicyNames(Endpoint? endpoint)
    {
        if (endpoint is null)
        {
            return [];
        }

        if (endpoint.Metadata.GetMetadata<GatewayRateLimitAttribute>() is { } attribute)
        {
            return attribute.PolicyNames;
        }

        if (endpoint.Metadata.GetMetadata<RouteModel>()?.Config.Metadata is { } metadata
            && metadata.TryGetValue(RouteMetadataKey, out var raw)
            && !string.IsNullOrWhiteSpace(raw))
        {
            return raw.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        }

        return [];
    }

    [LoggerMessage(EventId = 3010, Level = LogLevel.Warning,
        Message = "Route {RouteId} references unknown rate limit policy {PolicyName}; it is ignored")]
    private static partial void LogUnknownPolicy(ILogger logger, string policyName, string routeId);
}
