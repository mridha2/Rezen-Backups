using Avalonia.Controls;
using Avalonia.Input;
using RezenBackup.UI.ViewModels;

namespace RezenBackup.UI.Views;

public partial class MainWindow : Window
{
    public MainWindow()
    {
        InitializeComponent();
        AddHandler(PointerMovedEvent, (_, _) => Activity(), handledEventsToo: true);
        AddHandler(KeyDownEvent, (_, _) => Activity(), handledEventsToo: true);
        PropertyChanged += (_, e) =>
        {
            if (e.Property == WindowStateProperty && WindowState == WindowState.Minimized && DataContext is MainWindowViewModel vm)
            {
                vm.CurrentPage?.Ui.Locks.OnMinimized();
            }
        };
    }

    private void Activity()
    {
        if (DataContext is MainWindowViewModel { CurrentPage: { } page })
        {
            page.Ui.Locks.RegisterActivity();
        }
    }
}
