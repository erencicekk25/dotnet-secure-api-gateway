using NpgsqlTypes;
using SecureGateway.Gateway.Extensions;
using SecureGateway.Infrastructure;
using Serilog;
using Serilog.Events;
using Serilog.Filters;
using Serilog.Formatting.Compact;
using Serilog.Sinks.PostgreSQL;
using Serilog.Sinks.PostgreSQL.ColumnWriters;

namespace SecureGateway.Gateway.Logging;

public static class SerilogExtensions
{
    public const string HttpLogTableName = "http_logs";
    private const string RequestLoggingSource = "Serilog.AspNetCore.RequestLoggingMiddleware";

    /// <summary>
    /// Configures Serilog with two outputs:
    /// <list type="bullet">
    /// <item>Console: human readable locally, compact JSON elsewhere (ready for Loki / ELK / Datadog).</item>
    /// <item>PostgreSQL <c>http_logs</c>: one row per HTTP exchange plus every warning/error, with
    /// correlation id, client IP, user and route as first-class indexed-friendly columns.</item>
    /// </list>
    /// </summary>
    public static WebApplicationBuilder AddGatewaySerilog(this WebApplicationBuilder builder)
    {
        builder.Host.UseSerilog((context, services, logger) =>
        {
            logger
                .ReadFrom.Configuration(context.Configuration)
                .ReadFrom.Services(services)
                .Enrich.FromLogContext()
                .Enrich.WithProperty("Application", "SecureGateway")
                .Enrich.WithProperty("Environment", context.HostingEnvironment.EnvironmentName);

            if (context.HostingEnvironment.IsDevelopment())
            {
                logger.WriteTo.Console(
                    outputTemplate: "[{Timestamp:HH:mm:ss} {Level:u3}] [{CorrelationId}] {SourceContext}{NewLine}  {Message:lj}{NewLine}{Exception}");
            }
            else
            {
                logger.WriteTo.Console(new RenderedCompactJsonFormatter());
            }

            var connectionString = context.Configuration.GetConnectionString(DependencyInjection.AuditDatabaseConnectionName);
            var databaseSinkEnabled = context.Configuration.GetValue("Logging:Database:Enabled", true);

            if (databaseSinkEnabled && !string.IsNullOrWhiteSpace(connectionString))
            {
                var requestLogs = Matching.FromSource(RequestLoggingSource);

                logger.WriteTo.Logger(database => database
                    .Filter.ByIncludingOnly(e => e.Level >= LogEventLevel.Warning || requestLogs(e))
                    .WriteTo.PostgreSQL(
                        connectionString,
                        HttpLogTableName,
                        CreateColumnWriters(),
                        needAutoCreateTable: true));
            }
        });

        return builder;
    }

    /// <summary>Enriches the single "request completed" event emitted per HTTP exchange.</summary>
    public static IApplicationBuilder UseGatewayRequestLogging(this IApplicationBuilder app) =>
        app.UseSerilogRequestLogging(options =>
        {
            options.MessageTemplate =
                "HTTP {RequestMethod} {RequestPath} responded {StatusCode} in {Elapsed:0.000} ms (route {RouteId})";

            options.EnrichDiagnosticContext = static (diagnostics, httpContext) =>
            {
                diagnostics.Set("ClientIp", httpContext.GetClientIp());
                diagnostics.Set("UserId", httpContext.GetUserId() ?? "anonymous");
                diagnostics.Set("RouteId", httpContext.GetGatewayRouteId());
                diagnostics.Set("UserAgent", httpContext.Request.Headers.UserAgent.ToString());
            };

            options.GetLevel = static (httpContext, elapsedMs, exception) =>
                exception is not null || httpContext.Response.StatusCode >= StatusCodes.Status500InternalServerError
                    ? LogEventLevel.Error
                    : httpContext.Response.StatusCode >= StatusCodes.Status400BadRequest || elapsedMs > 2_000
                        ? LogEventLevel.Warning
                        : LogEventLevel.Information;
        });

    private static Dictionary<string, ColumnWriterBase> CreateColumnWriters() => new()
    {
        ["logged_at_utc"] = new TimestampColumnWriter(NpgsqlDbType.TimestampTz),
        ["level"] = new LevelColumnWriter(true, NpgsqlDbType.Varchar),
        ["correlation_id"] = new SinglePropertyColumnWriter("CorrelationId", PropertyWriteMethod.ToString, NpgsqlDbType.Varchar, "l"),
        ["request_method"] = new SinglePropertyColumnWriter("RequestMethod", PropertyWriteMethod.ToString, NpgsqlDbType.Varchar, "l"),
        ["request_path"] = new SinglePropertyColumnWriter("RequestPath", PropertyWriteMethod.ToString, NpgsqlDbType.Varchar, "l"),
        ["status_code"] = new SinglePropertyColumnWriter("StatusCode", PropertyWriteMethod.Raw, NpgsqlDbType.Integer),
        ["elapsed_ms"] = new SinglePropertyColumnWriter("Elapsed", PropertyWriteMethod.Raw, NpgsqlDbType.Double),
        ["route_id"] = new SinglePropertyColumnWriter("RouteId", PropertyWriteMethod.ToString, NpgsqlDbType.Varchar, "l"),
        ["client_ip"] = new SinglePropertyColumnWriter("ClientIp", PropertyWriteMethod.ToString, NpgsqlDbType.Varchar, "l"),
        ["user_id"] = new SinglePropertyColumnWriter("UserId", PropertyWriteMethod.ToString, NpgsqlDbType.Varchar, "l"),
        ["source_context"] = new SinglePropertyColumnWriter("SourceContext", PropertyWriteMethod.ToString, NpgsqlDbType.Varchar, "l"),
        ["message"] = new RenderedMessageColumnWriter(NpgsqlDbType.Text),
        ["exception"] = new ExceptionColumnWriter(NpgsqlDbType.Text),
        ["properties"] = new LogEventSerializedColumnWriter(NpgsqlDbType.Jsonb)
    };
}
