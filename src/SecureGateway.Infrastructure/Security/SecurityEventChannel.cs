using System.Threading.Channels;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SecureGateway.Application.Security;
using SecureGateway.Domain.Security;

namespace SecureGateway.Infrastructure.Security;

/// <summary>
/// Bounded, lock-free hand-off between request threads (producers) and the background
/// database writer (single consumer). Publishing is O(1) and never awaits I/O, so a slow or
/// unavailable audit database cannot add latency to proxied traffic.
/// </summary>
public sealed partial class SecurityEventChannel : ISecurityEventPublisher
{
    private readonly Channel<SecurityEvent> _channel;
    private readonly ILogger<SecurityEventChannel> _logger;
    private long _droppedCount;

    public SecurityEventChannel(IOptions<SecurityAuditOptions> options, ILogger<SecurityEventChannel> logger)
    {
        _logger = logger;
        _channel = Channel.CreateBounded<SecurityEvent>(new BoundedChannelOptions(options.Value.ChannelCapacity)
        {
            FullMode = BoundedChannelFullMode.Wait, // makes TryWrite return false instead of silently dropping
            SingleReader = true,
            SingleWriter = false
        });
    }

    public ChannelReader<SecurityEvent> Reader => _channel.Reader;

    public long DroppedCount => Interlocked.Read(ref _droppedCount);

    public bool Publish(SecurityEvent securityEvent)
    {
        // Every event is also emitted as a structured log, so it survives even if the buffer is full.
        LogSecurityEvent(
            _logger,
            securityEvent.EventType,
            securityEvent.Severity,
            securityEvent.CorrelationId,
            securityEvent.ClientIp,
            securityEvent.UserId,
            securityEvent.Path,
            securityEvent.Details);

        if (_channel.Writer.TryWrite(securityEvent))
        {
            return true;
        }

        var dropped = Interlocked.Increment(ref _droppedCount);
        LogEventDropped(_logger, securityEvent.EventType, dropped);
        return false;
    }

    public void Complete() => _channel.Writer.TryComplete();

    [LoggerMessage(
        EventId = 4000,
        Level = LogLevel.Warning,
        Message = "Security event {EventType} ({Severity}) correlation={CorrelationId} ip={ClientIp} user={UserId} path={Path}: {Details}")]
    private static partial void LogSecurityEvent(
        ILogger logger,
        SecurityEventType eventType,
        SecuritySeverity severity,
        string correlationId,
        string? clientIp,
        string? userId,
        string? path,
        string? details);

    [LoggerMessage(
        EventId = 4001,
        Level = LogLevel.Error,
        Message = "Security audit buffer is full; event {EventType} was not persisted. Total dropped: {DroppedCount}")]
    private static partial void LogEventDropped(ILogger logger, SecurityEventType eventType, long droppedCount);
}
