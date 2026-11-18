using SecureGateway.Gateway.Extensions;
using SecureGateway.Gateway.Logging;
using SecureGateway.Infrastructure;
using Serilog;

// Bootstrap logger captures failures that happen before the host (and its configuration) is built.
Log.Logger = new LoggerConfiguration()
    .WriteTo.Console()
    .CreateBootstrapLogger();

try
{
    var builder = WebApplication.CreateBuilder(args);

    builder.WebHost.ConfigureKestrel(kestrel =>
    {
        kestrel.AddServerHeader = false;                       // do not advertise the server stack
        kestrel.Limits.MaxRequestBodySize = 1 * 1024 * 1024;   // 1 MB is plenty for banking JSON APIs
        kestrel.Limits.MaxRequestHeadersTotalSize = 32 * 1024;
    });

    builder.AddGatewaySerilog();

    builder.Services
        .AddInfrastructure(builder.Configuration)
        .AddGatewayForwardedHeaders(builder.Configuration)
        .AddGatewaySecurity(builder.Configuration)
        .AddGatewayRateLimiting()
        .AddGatewayReverseProxy(builder.Configuration)
        .AddGatewayHttpDefaults();

    var app = builder.Build();

    app.UseGatewayPipeline();
    app.MapGatewayEndpoints();

    await app.RunAsync();
}
catch (Exception ex) when (ex is not HostAbortedException)
{
    Log.Fatal(ex, "Secure gateway terminated unexpectedly");
    Environment.ExitCode = 1;
}
finally
{
    await Log.CloseAndFlushAsync();
}

/// <summary>Exposed for integration testing with WebApplicationFactory.</summary>
public partial class Program;
