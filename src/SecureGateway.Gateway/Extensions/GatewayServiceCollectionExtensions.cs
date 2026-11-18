using System.Net;
using System.Text;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using SecureGateway.Gateway.Proxy;
using SecureGateway.Gateway.RateLimiting;
using SecureGateway.Gateway.Security;

namespace SecureGateway.Gateway.Extensions;

public static class GatewayServiceCollectionExtensions
{
    public static IServiceCollection AddGatewaySecurity(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddOptions<JwtOptions>()
            .Bind(configuration.GetSection(JwtOptions.SectionName))
            .ValidateDataAnnotations()
            .ValidateOnStart();

        services.AddOptions<DevTokenIssuerOptions>()
            .Bind(configuration.GetSection(DevTokenIssuerOptions.SectionName));

        services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme).AddJwtBearer();

        services.AddOptions<JwtBearerOptions>(JwtBearerDefaults.AuthenticationScheme)
            .Configure<IOptions<JwtOptions>>((bearer, jwtOptions) =>
            {
                var jwt = jwtOptions.Value;

                bearer.MapInboundClaims = false; // keep compact JWT claim names ("sub", "role", "scope")
                bearer.SaveToken = false;
                bearer.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidIssuer = jwt.Issuer,
                    ValidateAudience = true,
                    ValidAudience = jwt.Audience,
                    ValidateLifetime = true,
                    RequireExpirationTime = true,
                    RequireSignedTokens = true,
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwt.SigningKey)),
                    ValidAlgorithms = [SecurityAlgorithms.HmacSha256], // blocks "alg" confusion / downgrade
                    ClockSkew = TimeSpan.FromSeconds(jwt.ClockSkewSeconds),
                    NameClaimType = GatewayHttpContextExtensions.SubjectClaimType,
                    RoleClaimType = "role"
                };
                bearer.Events = GatewayJwtBearerEvents.Create();
            });

        services.AddAuthorization(GatewayPolicies.Register);
        services.AddSingleton<IAuthorizationMiddlewareResultHandler, AuditingAuthorizationResultHandler>();

        services.AddSingleton(TimeProvider.System);
        services.AddSingleton<DevTokenIssuer>();

        return services;
    }

    public static IServiceCollection AddGatewayRateLimiting(this IServiceCollection services)
    {
        // RateLimitingOptions and the Redis limiter are registered by the infrastructure layer.
        services.AddSingleton<IRateLimitPolicyResolver, RateLimitPolicyResolver>();
        return services;
    }

    public static IServiceCollection AddGatewayReverseProxy(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddReverseProxy()
            .LoadFromConfig(configuration.GetSection("ReverseProxy"))
            .AddTransforms(context => context.AddIdentityPropagation());

        return services;
    }

    /// <summary>
    /// Trusts <c>X-Forwarded-*</c> headers only from explicitly configured proxies / networks.
    /// With nothing configured the middleware is not added at all, so a client cannot spoof its IP
    /// to escape IP-based quotas.
    /// </summary>
    public static IServiceCollection AddGatewayForwardedHeaders(this IServiceCollection services, IConfiguration configuration)
    {
        var proxies = configuration.GetSection("ForwardedHeaders:KnownProxies").Get<string[]>() ?? [];
        var networks = configuration.GetSection("ForwardedHeaders:KnownNetworks").Get<string[]>() ?? [];

        services.Configure<ForwardedHeadersOptions>(options =>
        {
            options.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
            options.ForwardLimit = 1;
            options.KnownProxies.Clear();
            options.KnownNetworks.Clear();

            foreach (var proxy in proxies)
            {
                options.KnownProxies.Add(IPAddress.Parse(proxy));
            }

            foreach (var network in networks)
            {
                var parts = network.Split('/');
                options.KnownNetworks.Add(new Microsoft.AspNetCore.HttpOverrides.IPNetwork(
                    IPAddress.Parse(parts[0]), int.Parse(parts[1], System.Globalization.CultureInfo.InvariantCulture)));
            }
        });

        return services;
    }

    public static IServiceCollection AddGatewayHttpDefaults(this IServiceCollection services)
    {
        services.AddProblemDetails();
        services.ConfigureHttpJsonOptions(options =>
            options.SerializerOptions.Converters.Add(new JsonStringEnumConverter()));

        return services;
    }
}
