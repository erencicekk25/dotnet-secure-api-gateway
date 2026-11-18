using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SecureGateway.Application.Security;
using SecureGateway.Domain.Security;

namespace SecureGateway.Infrastructure.Security;

/// <summary>
/// Background consumer that drains <see cref="SecurityEventChannel"/> and persists events in batches.
/// Batching amortizes connection and round-trip costs, which keeps the audit trail cheap even during
/// an attack that produces thousands of events per second.
/// </summary>
public sealed partial class SecurityEventWriter(
    SecurityEventChannel channel,
    ISecurityEventStore store,
    IOptions<SecurityAuditOptions> options,
    ILogger<SecurityEventWriter> logger) : BackgroundService
{
    private static readonly TimeSpan ShutdownFlushTimeout = TimeSpan.FromSeconds(10);
    private readonly SecurityAuditOptions _options = options.Value;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!await InitializeStoreAsync(stoppingToken).ConfigureAwait(false))
        {
            return;
        }

        var batch = new List<SecurityEvent>(_options.BatchSize);
        var reader = channel.Reader;
        var flushInterval = TimeSpan.FromMilliseconds(_options.FlushIntervalMilliseconds);

        try
        {
            while (await reader.WaitToReadAsync(stoppingToken).ConfigureAwait(false))
            {
                using var flushWindow = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
                flushWindow.CancelAfter(flushInterval);

                // Accumulate until the batch is full or the flush interval elapses.
                while (batch.Count < _options.BatchSize)
                {
                    if (reader.TryRead(out var securityEvent))
                    {
                        batch.Add(securityEvent);
                        continue;
                    }

                    try
                    {
                        if (!await reader.WaitToReadAsync(flushWindow.Token).ConfigureAwait(false))
                        {
                            break;
                        }
                    }
                    catch (OperationCanceledException) when (!stoppingToken.IsCancellationRequested)
                    {
                        break; // flush interval elapsed
                    }
                }

                await FlushAsync(batch, stoppingToken).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            // Graceful shutdown: fall through to the final drain below.
        }

        await DrainOnShutdownAsync(batch).ConfigureAwait(false);
    }

    private async Task<bool> InitializeStoreAsync(CancellationToken stoppingToken)
    {
        var retryDelay = TimeSpan.FromSeconds(_options.InitializationRetrySeconds);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await store.InitializeAsync(stoppingToken).ConfigureAwait(false);
                LogStoreInitialized(logger);
                return true;
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                LogStoreInitializationFailed(logger, ex, retryDelay.TotalSeconds);
            }

            try
            {
                await Task.Delay(retryDelay, stoppingToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return false;
            }
        }

        return false;
    }

    private async Task FlushAsync(List<SecurityEvent> batch, CancellationToken cancellationToken)
    {
        if (batch.Count == 0)
        {
            return;
        }

        try
        {
            await store.WriteBatchAsync(batch, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // The events were already emitted to the structured log by the publisher,
            // so the trail is degraded, not lost. Never let the writer loop die.
            LogBatchWriteFailed(logger, ex, batch.Count);
        }
        finally
        {
            batch.Clear();
        }
    }

    private async Task DrainOnShutdownAsync(List<SecurityEvent> batch)
    {
        channel.Complete();
        using var timeout = new CancellationTokenSource(ShutdownFlushTimeout);

        while (channel.Reader.TryRead(out var securityEvent))
        {
            batch.Add(securityEvent);
            if (batch.Count >= _options.BatchSize)
            {
                await FlushAsync(batch, timeout.Token).ConfigureAwait(false);
            }
        }

        await FlushAsync(batch, timeout.Token).ConfigureAwait(false);
    }

    [LoggerMessage(EventId = 4100, Level = LogLevel.Information, Message = "Security audit store initialized")]
    private static partial void LogStoreInitialized(ILogger logger);

    [LoggerMessage(EventId = 4101, Level = LogLevel.Warning, Message = "Security audit store is not reachable yet; retrying in {RetrySeconds}s")]
    private static partial void LogStoreInitializationFailed(ILogger logger, Exception exception, double retrySeconds);

    [LoggerMessage(EventId = 4102, Level = LogLevel.Error, Message = "Failed to persist a batch of {Count} security events")]
    private static partial void LogBatchWriteFailed(ILogger logger, Exception exception, int count);
}
