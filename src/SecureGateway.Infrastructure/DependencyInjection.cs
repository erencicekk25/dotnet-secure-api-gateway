using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Options;
using Npgsql;
using SecureGateway.Application.RateLimiting;
using SecureGateway.Application.Security;
using SecureGateway.Infrastructure.HealthChecks;
using SecureGateway.Infrastructure.RateLimiting;
using SecureGateway.Infrastructure.Security;
using StackExchange.Redis;

namespace SecureGateway.Infrastructure;

public static class DependencyInjection
{
    public const string RedisConnectionName = "Redis";
    public const string AuditDatabaseConnectionName = "SecurityAudit";
    public const string ReadinessTag = "ready";

    public static IServiceCollection AddInfrastructure(this IServiceCollection services, IConfiguration configuration)
    {
        var redisConnectionString = GetRequiredConnectionString(configuration, RedisConnectionName);
        var auditConnectionString = GetRequiredConnectionString(configuration, AuditDatabaseConnectionName);

        // Rate limiting -----------------------------------------------------------------------
        services.AddOptions<RateLimitingOptions>()
            .Bind(configuration.GetSection(RateLimitingOptions.SectionName))
            .ValidateOnStart();
        services.AddSingleton<IValidateOptions<RateLimitingOptions>, RateLimitingOptionsValidator>();

        services.AddSingleton<IConnectionMultiplexer>(_ =>
        {
            var redisOptions = ConfigurationOptions.Parse(redisConnectionString);
            redisOptions.AbortOnConnectFail = false; // keep retrying in the background instead of crashing the host
            redisOptions.ClientName = "secure-gateway";
            return ConnectionMultiplexer.Connect(redisOptions);
        });
        services.AddSingleton<IRateLimiter, RedisSlidingWindowRateLimiter>();

        // Security audit trail ----------------------------------------------------------------
        services.AddOptions<SecurityAuditOptions>()
            .Bind(configuration.GetSection(SecurityAuditOptions.SectionName))
            .Validate(o => o.ChannelCapacity > 0 && o.BatchSize > 0 && o.FlushIntervalMilliseconds > 0,
                "SecurityAudit buffer settings must be positive.")
            .ValidateOnStart();

        services.AddSingleton(_ => NpgsqlDataSource.Create(auditConnectionString));
        services.AddSingleton<SecurityEventChannel>();
        services.AddSingleton<ISecurityEventPublisher>(sp => sp.GetRequiredService<SecurityEventChannel>());
        services.AddSingleton<ISecurityEventStore, PostgresSecurityEventStore>();
        services.AddHostedService<SecurityEventWriter>();

        // Health ------------------------------------------------------------------------------
        services.AddHealthChecks()
            .AddCheck<RedisHealthCheck>("redis", HealthStatus.Unhealthy, [ReadinessTag])
            .AddCheck<PostgresHealthCheck>("postgres", HealthStatus.Degraded, [ReadinessTag]);

        return services;
    }

    private static string GetRequiredConnectionString(IConfiguration configuration, string name) =>
        configuration.GetConnectionString(name) is { Length: > 0 } value
            ? value
            : throw new InvalidOperationException(
                $"Connection string '{name}' is not configured. See .env.example for the expected variables.");
}
