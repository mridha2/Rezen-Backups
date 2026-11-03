using System.Runtime.CompilerServices;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Headless;
using Avalonia.Interactivity;
using Avalonia.Logging;
using Avalonia.Threading;
using Avalonia.VisualTree;
using RezenBackup.Application;
using RezenBackup.Core.Platform;
using RezenBackup.Crypto;
using RezenBackup.UI.Services;
using RezenBackup.UI.Views;

[assembly: AvaloniaTestApplication(typeof(RezenBackup.UI.Tests.TestAppBuilder))]

namespace RezenBackup.UI.Tests;

public static class TestAppBuilder
{
    public static AppBuilder BuildAvaloniaApp() =>
        AppBuilder.Configure<App>().UseHeadless(new AvaloniaHeadlessPlatformOptions { UseHeadlessDrawing = true });

    [ModuleInitializer]
    internal static void Init()
    {
        KdfPolicy.UseForTesting(new KdfParameters(8 * 1024, 1, 1));
        Logger.Sink = BindingErrors.Sink;
    }
}

/// <summary>Collects Avalonia binding errors so tests fail on a broken binding instead of a silently empty field.</summary>
public static class BindingErrors
{
    public static readonly ListSink Sink = new();

    public sealed class ListSink : ILogSink
    {
        private readonly List<string> _errors = [];

        public IReadOnlyList<string> Errors
        {
            get
            {
                lock (_errors)
                {
                    return _errors.ToList();
                }
            }
        }

        public void Clear()
        {
            lock (_errors)
            {
                _errors.Clear();
            }
        }

        public bool IsEnabled(LogEventLevel level, string area) => level >= LogEventLevel.Warning && area == LogArea.Binding;

        public void Log(LogEventLevel level, string area, object? source, string messageTemplate) => Add(messageTemplate, []);

        public void Log(LogEventLevel level, string area, object? source, string messageTemplate, params object?[] propertyValues) => Add(messageTemplate, propertyValues);

        private void Add(string template, object?[] values)
        {
            var text = template + " | " + string.Join(", ", values.Select(v => v?.ToString()));

            // A page being navigated away from loses its DataContext while its item templates are torn down; those
            // transient "$parent ... DataContext ... Value is null" messages are not real binding defects.
            if (text.Contains("$parent[", StringComparison.Ordinal) && text.Contains("DataContext, Value is null", StringComparison.Ordinal))
            {
                return;
            }

            lock (_errors)
            {
                _errors.Add(text);
            }
        }
    }
}

/// <summary>Answers modal dialogs as they open (clicks buttons by caption, types into text boxes).</summary>
public static class DialogDriver
{
    private static readonly Queue<Action<Window>> Handlers = new();

    static DialogDriver()
    {
        Window.WindowOpenedEvent.AddClassHandler<Window>((w, _) =>
        {
            if (w is MainWindow)
            {
                return;
            }

            Opened.Add(w.Title ?? string.Empty);
            if (Handlers.TryDequeue(out var handler))
            {
                Dispatcher.UIThread.Post(() => handler(w), DispatcherPriority.Background);
            }
        });
    }

    public static List<string> Opened { get; } = [];

    public static void Enqueue(Action<Window> handler) => Handlers.Enqueue(handler);

    public static void Reset()
    {
        Handlers.Clear();
        Opened.Clear();
    }

    public static void Click(Window w, string caption)
    {
        var button = w.GetVisualDescendants().OfType<Button>().FirstOrDefault(b => Equals(b.Content, caption))
            ?? throw new InvalidOperationException($"No button '{caption}' in dialog '{w.Title}'.");
        button.RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
    }

    public static void Type(Window w, string text, int index = 0) =>
        w.GetVisualDescendants().OfType<TextBox>().ElementAt(index).Text = text;

    public static void Answer(string caption) => Enqueue(w => Click(w, caption));

    public static void Unlock(string password) => Enqueue(w =>
    {
        Type(w, password);
        Click(w, "Unlock");
    });
}

/// <summary>A full app instance in temporary folders with a fake removable drive and no OS integration.</summary>
public sealed class UiFixture : IDisposable
{
    public const string Password = "orange tractor singing quietly 42";

    public UiFixture()
    {
        Root = Path.Combine(Path.GetTempPath(), "rezen-ui-" + Guid.NewGuid().ToString("N")[..10]);
        Drive = Path.Combine(Root, "drive");
        Source = Path.Combine(Root, "Documents");
        Directory.CreateDirectory(Drive);
        Directory.CreateDirectory(Path.Combine(Source, "Invoices"));
        File.WriteAllText(Path.Combine(Source, "Budget.xlsx"), "budget v1");
        File.WriteAllText(Path.Combine(Source, "Invoices", "Invoice-1843.pdf"), "invoice");
        var platform = new PlatformServices(
            new MemoryCredentials(),
            PortableDurableFileOps.Instance,
            PortableFileMetadataProvider.Instance,
            LiveSourceSnapshotProvider.Instance,
            new NoPower(),
            new NoNotify(),
            new NoAutostart(),
            new OneVolume(Drive),
            new NeverLocked(),
            "test");
        App = RezenApp.Create(new AppPaths(Path.Combine(Root, "appdata")), platform);
        // Never spawn a background agent process from tests.
        App.SaveSettings(App.Settings with { RunBackgroundAgent = false, StartWithSystem = false });
        Ui = new UiContext(App);
    }

    public string Root { get; }

    public string Drive { get; }

    public string Source { get; }

    public RezenApp App { get; }

    public UiContext Ui { get; }

    public static async Task WaitUntil(Func<bool> condition, int timeoutMs = 20_000)
    {
        var deadline = DateTime.UtcNow.AddMilliseconds(timeoutMs);
        while (!condition())
        {
            if (DateTime.UtcNow > deadline)
            {
                throw new TimeoutException("Condition not met in time.");
            }

            Dispatcher.UIThread.RunJobs();
            await Task.Delay(20);
        }
    }

    public void Dispose()
    {
        Ui.Dispose();
        App.Dispose();
        try
        {
            Directory.Delete(Root, true);
        }
        catch (IOException)
        {
        }
    }

    private sealed class MemoryCredentials : ICredentialStore
    {
        private readonly Dictionary<Guid, byte[]> _items = [];

        public bool IsSupported => true;

        public string MechanismName => "test store";

        public void Save(Guid keySetId, RootSecret secret) => _items[keySetId] = secret.Bytes.ToArray();

        public RootSecret? TryLoad(Guid keySetId) => _items.TryGetValue(keySetId, out var b) && b.Length == RootSecret.Length ? RootSecret.FromBytes(b) : null;

        public void SaveBytes(Guid id, ReadOnlySpan<byte> secret) => _items[id] = secret.ToArray();

        public SecretBuffer? TryLoadBytes(Guid id) => _items.TryGetValue(id, out var b) ? SecretBuffer.CopyFrom(b) : null;

        public bool Exists(Guid keySetId) => _items.ContainsKey(keySetId);

        public void Delete(Guid keySetId) => _items.Remove(keySetId);
    }

    private sealed class OneVolume(string root) : IVolumeInspector
    {
        public IReadOnlyList<VolumeInfo> GetVolumes() => [new VolumeInfo(root, "TEST-DRIVE", "APFS", 1L << 40, 1L << 39, true, "uuid")];

        public VolumeInfo? GetVolumeForPath(string path) => Path.GetFullPath(path).StartsWith(root, StringComparison.Ordinal) ? GetVolumes()[0] : null;

        public bool TryEject(string rootPath) => true;
    }

    private sealed class NoPower : IPowerManager
    {
        public IDisposable KeepAwake(string reason) => new Noop();

        public bool IsOnBattery => false;

        private sealed class Noop : IDisposable
        {
            public void Dispose()
            {
            }
        }
    }

    private sealed class NoNotify : INotifier
    {
        public void Notify(string title, string message, NotificationKind kind)
        {
        }
    }

    private sealed class NoAutostart : IAutostart
    {
        public bool IsEnabled => false;

        public void Enable(string agentExecutablePath)
        {
        }

        public void Disable()
        {
        }
    }

    private sealed class NeverLocked : ISessionStateMonitor
    {
        public bool IsSystemLocked() => false;
    }
}
