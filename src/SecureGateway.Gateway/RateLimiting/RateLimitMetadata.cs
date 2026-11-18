namespace SecureGateway.Gateway.RateLimiting;

/// <summary>
/// Assigns one or more named quota policies to a gateway-local endpoint.
/// Proxied YARP routes declare the same thing through the <c>RateLimitPolicies</c> route metadata key.
/// </summary>
[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method)]
public sealed class GatewayRateLimitAttribute(params string[] policyNames) : Attribute
{
    public IReadOnlyList<string> PolicyNames { get; } = policyNames;
}

/// <summary>Excludes an endpoint from distributed rate limiting (e.g. orchestrator health probes).</summary>
[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method)]
public sealed class DisableGatewayRateLimitAttribute : Attribute;
