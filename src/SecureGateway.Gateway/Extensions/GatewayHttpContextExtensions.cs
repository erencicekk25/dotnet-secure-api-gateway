using SecureGateway.Gateway.Middleware;
using Yarp.ReverseProxy.Model;

namespace SecureGateway.Gateway.Extensions;

public static class GatewayHttpContextExtensions
{
    public const string SubjectClaimType = "sub";
    public const string UnmatchedRouteId = "unmatched";

    public static string GetCorrelationId(this HttpContext context) =>
        context.Items.TryGetValue(CorrelationIdMiddleware.ItemKey, out var value) && value is string id
            ? id
            : context.TraceIdentifier;

    /// <summary>
    /// Returns the client IP as seen by the gateway. When trusted proxies are configured the
    /// forwarded-headers middleware has already rewritten <see cref="ConnectionInfo.RemoteIpAddress"/>;
    /// raw <c>X-Forwarded-For</c> values are never trusted directly.
    /// </summary>
    public static string GetClientIp(this HttpContext context)
    {
        var address = context.Connection.RemoteIpAddress;
        if (address is null)
        {
            return "unknown";
        }

        return address.IsIPv4MappedToIPv6 ? address.MapToIPv4().ToString() : address.ToString();
    }

    public static string? GetUserId(this HttpContext context) =>
        context.User.Identity?.IsAuthenticated == true
            ? context.User.FindFirst(SubjectClaimType)?.Value
            : null;

    /// <summary>Stable identifier of the matched route: the YARP route id, or the route pattern of a local endpoint.</summary>
    public static string GetGatewayRouteId(this HttpContext context)
    {
        var endpoint = context.GetEndpoint();
        if (endpoint is null)
        {
            return UnmatchedRouteId;
        }

        if (endpoint.Metadata.GetMetadata<RouteModel>() is { } proxyRoute)
        {
            return proxyRoute.Config.RouteId;
        }

        return endpoint is RouteEndpoint { RoutePattern.RawText: { Length: > 0 } pattern }
            ? pattern
            : endpoint.DisplayName ?? UnmatchedRouteId;
    }
}
