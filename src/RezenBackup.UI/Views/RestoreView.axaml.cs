using Avalonia.Controls;
using Avalonia.Input;
using RezenBackup.UI.ViewModels;

namespace RezenBackup.UI.Views;

public partial class RestoreView : UserControl
{
    public RestoreView() => InitializeComponent();

    private void OnBrowserDoubleTapped(object? sender, TappedEventArgs e)
    {
        if (DataContext is RestoreViewModel vm && vm.SelectedItem is { IsDirectory: true } item)
        {
            vm.OpenCommand.Execute(item);
        }
    }
}
