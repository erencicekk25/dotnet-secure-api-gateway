using Microsoft.AspNetCore.Diagnostics.HealthChecks;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.Extensions.Options;
using SecureGateway.Gateway.Endpoints;
using SecureGateway.Gateway.Logging;
using SecureGateway.Gateway.Middleware;
using SecureGateway.Gateway.RateLimiting;
using SecureGateway.Gateway.Security;
using SecureGateway.Infrastructure;

namespace SecureGateway.Gateway.Extensions;

public static class GatewayApplicationBuilderExtensions
{
    /// <summary>
    /// The order of this pipeline is a security decision, not a style choice:
    /// <code>
    /// ForwardedHeaders → CorrelationId → SecurityHeaders → ExceptionHandler → RequestLogging
    ///   → Routing → Authentication → RateLimiting → Authorization → Endpoint (YARP / local)
    /// </code>
    /// </summary>
    public static WebApplication UseGatewayPipeline(this WebApplication app)
    {
        var forwardedOptions = app.Services.GetRequiredService<IOptions<ForwardedHeadersOptions>>().Value;
        if (forwardedOptions.KnownProxies.Count > 0 || forwardedOptions.KnownNetworks.Count > 0)
        {
            app.UseForwardedHeaders();
        }

        app.UseMiddleware<CorrelationIdMiddleware>();      // 1. every log line below carries the id
        app.UseMiddleware<SecurityHeadersMiddleware>();    // 2. applies even to error responses
        app.UseExceptionHandler();                         // 3. no stack traces leak to clients
        app.UseGatewayRequestLogging();                    // 4. one structured audit line per exchange
        app.UseRouting();                                  // 5. resolve route → policies
        app.UseAuthentication();                           // 6. who is calling?
        app.UseMiddleware<GatewayRateLimitingMiddleware>(); // 7. may they call this often?
        app.UseAuthorization();                            // 8. may they call this at all?

        return app;
    }

    public static WebApplication MapGatewayEndpoints(this WebApplication app)
    {
        app.MapHealthChecks("/health/live", new HealthCheckOptions { Predicate = _ => false })
            .AllowAnonymous()
            .WithMetadata(new DisableGatewayRateLimitAttribute());

        app.MapHealthChecks("/health/ready", new HealthCheckOptions
            {
                Predicate = registration => registration.Tags.Contains(DependencyInjection.ReadinessTag)
            })
            .AllowAnonymous()
            .WithMetadata(new DisableGatewayRateLimitAttribute());

        app.MapSecurityEventEndpoints();

        var devTokens = app.Services.GetRequiredService<IOptions<DevTokenIssuerOptions>>().Value;
        if (devTokens.Enabled && !app.Environment.IsProduction())
        {
            app.Logger.LogWarning(
                "Development token issuer is ENABLED at {Path}. Never enable it outside local environments",
                DevTokenEndpoints.Path);
            app.MapDevTokenEndpoint();
        }

        app.MapReverseProxy();

        return app;
    }
}
