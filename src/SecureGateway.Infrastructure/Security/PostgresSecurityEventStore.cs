using Npgsql;
using NpgsqlTypes;
using SecureGateway.Application.Security;
using SecureGateway.Domain.Security;

namespace SecureGateway.Infrastructure.Security;

/// <summary>
/// PostgreSQL implementation of the security audit trail.
/// Writes use the binary <c>COPY</c> protocol, the fastest bulk-ingest path PostgreSQL offers.
/// </summary>
public sealed class PostgresSecurityEventStore(NpgsqlDataSource dataSource) : ISecurityEventStore
{
    private const string SchemaSql = """
        CREATE TABLE IF NOT EXISTS security_events (
            id               uuid          PRIMARY KEY,
            occurred_at_utc  timestamptz   NOT NULL,
            event_type       varchar(64)   NOT NULL,
            severity         varchar(16)   NOT NULL,
            correlation_id   varchar(64)   NOT NULL,
            client_ip        varchar(64)   NULL,
            user_id          varchar(256)  NULL,
            http_method      varchar(16)   NULL,
            path             varchar(2048) NULL,
            route_id         varchar(128)  NULL,
            status_code      integer       NULL,
            details          text          NULL
        );
        CREATE INDEX IF NOT EXISTS ix_security_events_occurred_at    ON security_events (occurred_at_utc DESC);
        CREATE INDEX IF NOT EXISTS ix_security_events_type_occurred  ON security_events (event_type, occurred_at_utc DESC);
        CREATE INDEX IF NOT EXISTS ix_security_events_correlation_id ON security_events (correlation_id);
        CREATE INDEX IF NOT EXISTS ix_security_events_client_ip      ON security_events (client_ip, occurred_at_utc DESC);
        """;

    private const string CopySql = """
        COPY security_events (id, occurred_at_utc, event_type, severity, correlation_id, client_ip,
                              user_id, http_method, path, route_id, status_code, details)
        FROM STDIN (FORMAT BINARY)
        """;

    private const string SelectSql = """
        SELECT id, occurred_at_utc, event_type, severity, correlation_id, client_ip,
               user_id, http_method, path, route_id, status_code, details
        FROM security_events
        WHERE (@event_type::varchar IS NULL OR event_type = @event_type)
        ORDER BY occurred_at_utc DESC
        LIMIT @take
        """;

    public async Task InitializeAsync(CancellationToken cancellationToken)
    {
        await using var command = dataSource.CreateCommand(SchemaSql);
        await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task WriteBatchAsync(IReadOnlyCollection<SecurityEvent> events, CancellationToken cancellationToken)
    {
        if (events.Count == 0)
        {
            return;
        }

        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        await using var importer = await connection.BeginBinaryImportAsync(CopySql, cancellationToken).ConfigureAwait(false);

        foreach (var e in events)
        {
            await importer.StartRowAsync(cancellationToken).ConfigureAwait(false);
            await importer.WriteAsync(e.Id, NpgsqlDbType.Uuid, cancellationToken).ConfigureAwait(false);
            await importer.WriteAsync(e.OccurredAtUtc.UtcDateTime, NpgsqlDbType.TimestampTz, cancellationToken).ConfigureAwait(false);
            await importer.WriteAsync(e.EventType.ToString(), NpgsqlDbType.Varchar, cancellationToken).ConfigureAwait(false);
            await importer.WriteAsync(e.Severity.ToString(), NpgsqlDbType.Varchar, cancellationToken).ConfigureAwait(false);
            await importer.WriteAsync(Truncate(e.CorrelationId, 64)!, NpgsqlDbType.Varchar, cancellationToken).ConfigureAwait(false);
            await WriteNullableAsync(importer, Truncate(e.ClientIp, 64), NpgsqlDbType.Varchar, cancellationToken).ConfigureAwait(false);
            await WriteNullableAsync(importer, Truncate(e.UserId, 256), NpgsqlDbType.Varchar, cancellationToken).ConfigureAwait(false);
            await WriteNullableAsync(importer, Truncate(e.HttpMethod, 16), NpgsqlDbType.Varchar, cancellationToken).ConfigureAwait(false);
            await WriteNullableAsync(importer, Truncate(e.Path, 2048), NpgsqlDbType.Varchar, cancellationToken).ConfigureAwait(false);
            await WriteNullableAsync(importer, Truncate(e.RouteId, 128), NpgsqlDbType.Varchar, cancellationToken).ConfigureAwait(false);

            if (e.StatusCode is { } statusCode)
            {
                await importer.WriteAsync(statusCode, NpgsqlDbType.Integer, cancellationToken).ConfigureAwait(false);
            }
            else
            {
                await importer.WriteNullAsync(cancellationToken).ConfigureAwait(false);
            }

            await WriteNullableAsync(importer, e.Details, NpgsqlDbType.Text, cancellationToken).ConfigureAwait(false);
        }

        await importer.CompleteAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task<IReadOnlyList<SecurityEvent>> QueryRecentAsync(
        int take,
        SecurityEventType? eventType,
        CancellationToken cancellationToken)
    {
        await using var command = dataSource.CreateCommand(SelectSql);
        command.Parameters.Add(new NpgsqlParameter("event_type", NpgsqlDbType.Varchar)
        {
            Value = eventType?.ToString() ?? (object)DBNull.Value
        });
        command.Parameters.Add(new NpgsqlParameter("take", NpgsqlDbType.Integer) { Value = Math.Clamp(take, 1, 500) });

        var results = new List<SecurityEvent>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);

        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            results.Add(new SecurityEvent
            {
                Id = reader.GetGuid(0),
                OccurredAtUtc = new DateTimeOffset(reader.GetDateTime(1), TimeSpan.Zero),
                EventType = Enum.Parse<SecurityEventType>(reader.GetString(2)),
                Severity = Enum.Parse<SecuritySeverity>(reader.GetString(3)),
                CorrelationId = reader.GetString(4),
                ClientIp = reader.IsDBNull(5) ? null : reader.GetString(5),
                UserId = reader.IsDBNull(6) ? null : reader.GetString(6),
                HttpMethod = reader.IsDBNull(7) ? null : reader.GetString(7),
                Path = reader.IsDBNull(8) ? null : reader.GetString(8),
                RouteId = reader.IsDBNull(9) ? null : reader.GetString(9),
                StatusCode = reader.IsDBNull(10) ? null : reader.GetInt32(10),
                Details = reader.IsDBNull(11) ? null : reader.GetString(11)
            });
        }

        return results;
    }

    private static Task WriteNullableAsync(
        NpgsqlBinaryImporter importer,
        string? value,
        NpgsqlDbType type,
        CancellationToken cancellationToken) =>
        value is null
            ? importer.WriteNullAsync(cancellationToken)
            : importer.WriteAsync(value, type, cancellationToken);

    private static string? Truncate(string? value, int maxLength) =>
        value is null || value.Length <= maxLength ? value : value[..maxLength];
}
