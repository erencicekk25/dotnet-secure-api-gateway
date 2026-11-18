using SecureGateway.Gateway.Extensions;
using Yarp.ReverseProxy.Transforms;
using Yarp.ReverseProxy.Transforms.Builder;

namespace SecureGateway.Gateway.Proxy;

/// <summary>
/// Propagates the identity validated at the edge to downstream services as trusted headers.
/// </summary>
/// <remarks>
/// Any inbound header using the reserved <c>X-Gateway-</c> names is removed first. Without that step
/// a caller could forge <c>X-Gateway-User-Id</c> and impersonate another customer towards services
/// that trust the gateway. Downstream services must only be reachable through the gateway network.
/// </remarks>
public static class IdentityPropagationTransform
{
    public const string UserIdHeader = "X-Gateway-User-Id";
    public const string UserRolesHeader = "X-Gateway-User-Roles";
    public const string ClientIpHeader = "X-Gateway-Client-Ip";

    private static readonly string[] ReservedHeaders = [UserIdHeader, UserRolesHeader, ClientIpHeader];

    public static TransformBuilderContext AddIdentityPropagation(this TransformBuilderContext builder)
    {
        builder.AddRequestTransform(static transformContext =>
        {
            var headers = transformContext.ProxyRequest.Headers;
            foreach (var reserved in ReservedHeaders)
            {
                headers.Remove(reserved);
            }

            var httpContext = transformContext.HttpContext;
            headers.TryAddWithoutValidation(ClientIpHeader, httpContext.GetClientIp());

            if (httpContext.GetUserId() is { } userId)
            {
                headers.TryAddWithoutValidation(UserIdHeader, userId);

                var roles = httpContext.User.FindAll("role").Select(c => c.Value).ToArray();
                if (roles.Length > 0)
                {
                    headers.TryAddWithoutValidation(UserRolesHeader, string.Join(',', roles));
                }
            }

            return ValueTask.CompletedTask;
        });

        return builder;
    }
}
