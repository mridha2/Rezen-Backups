using System.Collections.Concurrent;
using System.Globalization;
using System.Text;
using Microsoft.Extensions.Logging;

namespace RezenBackup.Logging;

/// <summary>
/// Local rolling file logger (one file per day, 30 days kept). Messages and exception text are scrubbed of paths when
/// "Hide filenames from logs" is on. Logs never leave the computer.
/// </summary>
public sealed class FileLoggerProvider : ILoggerProvider
{
    private readonly string _directory;
    private readonly string _prefix;
    private readonly object _gate = new();
    private readonly ConcurrentDictionary<string, FileLogger> _loggers = new();
    private StreamWriter? _writer;
    private string? _currentDate;

    public FileLoggerProvider(string directory, string prefix = "rezen", int retentionDays = 30)
    {
        _directory = directory;
        _prefix = prefix;
        Directory.CreateDirectory(directory);
        Prune(retentionDays);
    }

    public LogLevel MinimumLevel { get; set; } = LogLevel.Information;

    public ILogger CreateLogger(string categoryName) => _loggers.GetOrAdd(categoryName, c => new FileLogger(this, c));

    internal void Write(LogLevel level, string category, string message, Exception? exception)
    {
        var now = DateTimeOffset.Now;
        var sb = new StringBuilder(256);
        sb.Append(now.ToString("yyyy-MM-dd HH:mm:ss.fff zzz", CultureInfo.InvariantCulture))
          .Append(" [").Append(Short(level)).Append("] ")
          .Append(category.Replace("RezenBackup.", string.Empty, StringComparison.Ordinal)).Append(": ")
          .Append(LogPrivacy.Scrub(message));
        if (exception is not null)
        {
            sb.AppendLine().Append("    ").Append(exception.GetType().Name).Append(": ").Append(LogPrivacy.Scrub(exception.Message));
            if (exception.StackTrace is { } st)
            {
                sb.AppendLine().Append(LogPrivacy.Scrub(st));
            }
        }

        lock (_gate)
        {
            try
            {
                var date = now.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);
                if (_writer is null || date != _currentDate)
                {
                    _writer?.Dispose();
                    _currentDate = date;
                    var path = Path.Combine(_directory, $"{_prefix}-{date}.log");
                    _writer = new StreamWriter(new FileStream(path, FileMode.Append, FileAccess.Write, FileShare.ReadWrite | FileShare.Delete), Encoding.UTF8) { AutoFlush = true };
                }

                _writer.WriteLine(sb.ToString());
            }
            catch (IOException)
            {
                // Logging must never break a backup.
            }
        }
    }

    private static string Short(LogLevel level) => level switch
    {
        LogLevel.Trace => "TRC",
        LogLevel.Debug => "DBG",
        LogLevel.Information => "INF",
        LogLevel.Warning => "WRN",
        LogLevel.Error => "ERR",
        LogLevel.Critical => "CRT",
        _ => "---",
    };

    private void Prune(int retentionDays)
    {
        try
        {
            foreach (var f in Directory.EnumerateFiles(_directory, _prefix + "-*.log"))
            {
                if (File.GetLastWriteTimeUtc(f) < DateTime.UtcNow.AddDays(-retentionDays))
                {
                    File.Delete(f);
                }
            }
        }
        catch (IOException)
        {
        }
    }

    public IReadOnlyList<string> LogFiles() =>
        Directory.EnumerateFiles(_directory, "*.log").OrderByDescending(f => f, StringComparer.Ordinal).ToList();

    public void Dispose()
    {
        lock (_gate)
        {
            _writer?.Dispose();
            _writer = null;
        }
    }

    private sealed class FileLogger(FileLoggerProvider provider, string category) : ILogger
    {
        public IDisposable? BeginScope<TState>(TState state)
            where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => logLevel >= provider.MinimumLevel && logLevel != LogLevel.None;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            if (!IsEnabled(logLevel))
            {
                return;
            }

            provider.Write(logLevel, category, formatter(state, exception), exception);
        }
    }
}
