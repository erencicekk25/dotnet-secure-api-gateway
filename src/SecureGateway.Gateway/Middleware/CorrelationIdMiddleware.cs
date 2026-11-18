using System.Diagnostics;
using Serilog.Context;

namespace SecureGateway.Gateway.Middleware;

/// <summary>
/// Guarantees that every request carries a correlation id, makes it the ASP.NET trace identifier,
/// pushes it into the logging scope, forwards it to downstream services and echoes it to the caller.
/// </summary>
/// <remarks>
/// A client-supplied id is honoured only if it passes strict validation (length and character set);
/// otherwise a new one is generated. This prevents log injection and unbounded header values while
/// still allowing a calling system (e.g. a mobile banking BFF) to stitch its own traces together.
/// </remarks>
public sealed class CorrelationIdMiddleware(RequestDelegate next)
{
    public const string HeaderName = "X-Correlation-ID";
    public const string LogPropertyName = "CorrelationId";
    public const int MaxLength = 64;

    internal static readonly object ItemKey = new();

    public async Task InvokeAsync(HttpContext context)
    {
        var correlationId = IsValid(context.Request.Headers[HeaderName])
            ? context.Request.Headers[HeaderName].ToString()
            : Guid.NewGuid().ToString("N");

        context.Items[ItemKey] = correlationId;
        context.TraceIdentifier = correlationId;

        // Overwrite the inbound header so that YARP forwards exactly the validated value downstream.
        context.Request.Headers[HeaderName] = correlationId;

        Activity.Current?.SetTag("correlation.id", correlationId);

        context.Response.OnStarting(static state =>
        {
            var (httpContext, id) = ((HttpContext, string))state;
            httpContext.Response.Headers[HeaderName] = id;
            return Task.CompletedTask;
        }, (context, correlationId));

        using (LogContext.PushProperty(LogPropertyName, correlationId))
        {
            await next(context);
        }
    }

    public static bool IsValid(string? candidate)
    {
        if (string.IsNullOrEmpty(candidate) || candidate.Length > MaxLength)
        {
            return false;
        }

        foreach (var c in candidate)
        {
            if (!char.IsAsciiLetterOrDigit(c) && c is not ('-' or '_' or '.'))
            {
                return false;
            }
        }

        return true;
    }
}
