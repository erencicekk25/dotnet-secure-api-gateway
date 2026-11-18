namespace SecureGateway.Gateway.Middleware;

/// <summary>
/// Applies a hardened set of response headers to every response leaving the gateway,
/// including responses produced by downstream services, and strips headers that leak
/// implementation details of the internal estate.
/// </summary>
public sealed class SecurityHeadersMiddleware(RequestDelegate next)
{
    private static readonly string[] HeadersToStrip = ["Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"];

    public Task InvokeAsync(HttpContext context)
    {
        context.Response.OnStarting(static state =>
        {
            var httpContext = (HttpContext)state;
            var headers = httpContext.Response.Headers;

            foreach (var header in HeadersToStrip)
            {
                headers.Remove(header);
            }

            headers.XContentTypeOptions = "nosniff";
            headers.XFrameOptions = "DENY";
            headers["Referrer-Policy"] = "no-referrer";
            headers.ContentSecurityPolicy = "default-src 'none'; frame-ancestors 'none'";
            headers["Cross-Origin-Resource-Policy"] = "same-origin";

            // Financial data must never be cached by intermediaries unless a service explicitly opts in.
            if (string.IsNullOrEmpty(headers.CacheControl))
            {
                headers.CacheControl = "no-store";
            }

            if (httpContext.Request.IsHttps)
            {
                headers.StrictTransportSecurity = "max-age=31536000; includeSubDomains";
            }

            return Task.CompletedTask;
        }, context);

        return next(context);
    }
}
