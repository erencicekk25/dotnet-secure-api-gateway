using Microsoft.Extensions.Diagnostics.HealthChecks;
using Npgsql;

namespace SecureGateway.Infrastructure.HealthChecks;

public sealed class PostgresHealthCheck(NpgsqlDataSource dataSource) : IHealthCheck
{
    public async Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken cancellationToken = default)
    {
        try
        {
            await using var command = dataSource.CreateCommand("SELECT 1");
            await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false);
            return HealthCheckResult.Healthy("PostgreSQL is reachable.");
        }
        catch (Exception ex)
        {
            return new HealthCheckResult(context.Registration.FailureStatus, "PostgreSQL is unreachable.", ex);
        }
    }
}
