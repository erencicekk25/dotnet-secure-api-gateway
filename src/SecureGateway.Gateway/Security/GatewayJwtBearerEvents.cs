using Microsoft.AspNetCore.Authentication.JwtBearer;
using SecureGateway.Application.Security;
using SecureGateway.Domain.Security;
using SecureGateway.Gateway.Extensions;

namespace SecureGateway.Gateway.Security;

/// <summary>
/// JWT bearer event hooks: audit invalid tokens and return consistent problem-details bodies
/// (with correlation id) instead of empty 401/403 responses.
/// </summary>
internal static class GatewayJwtBearerEvents
{
    public static JwtBearerEvents Create() => new()
    {
        OnAuthenticationFailed = context =>
        {
            var publisher = context.HttpContext.RequestServices.GetRequiredService<ISecurityEventPublisher>();

            // Record the failure category only; exception messages may echo token content.
            publisher.Publish(SecurityEventFactory.Create(
                context.HttpContext,
                SecurityEventType.AuthenticationFailed,
                SecuritySeverity.High,
                StatusCodes.Status401Unauthorized,
                $"Token rejected: {context.Exception.GetType().Name}"));

            return Task.CompletedTask;
        },

        OnChallenge = async context =>
        {
            context.HandleResponse();
            context.Response.Headers.WWWAuthenticate = context.AuthenticateFailure is null
                ? "Bearer"
                : "Bearer error=\"invalid_token\"";

            await GatewayProblemDetails.WriteAsync(
                context.HttpContext,
                StatusCodes.Status401Unauthorized,
                "Unauthorized",
                "A valid bearer token is required to access this resource.");
        },

        OnForbidden = context => GatewayProblemDetails.WriteAsync(
            context.HttpContext,
            StatusCodes.Status403Forbidden,
            "Forbidden",
            "The caller is authenticated but lacks the role or scope required for this resource.")
    };
}
