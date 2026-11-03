using Avalonia.Controls;
using Avalonia.Controls.Templates;
using RezenBackup.UI.ViewModels;

namespace RezenBackup.UI;

/// <summary>Resolves <c>FooViewModel</c> to <c>FooView</c> in the Views namespace.</summary>
public sealed class ViewLocator : IDataTemplate
{
    public Control? Build(object? param)
    {
        if (param is null)
        {
            return null;
        }

        var name = param.GetType().FullName!.Replace(".ViewModels.", ".Views.", StringComparison.Ordinal).Replace("ViewModel", "View", StringComparison.Ordinal);
        var type = Type.GetType(name);
        return type is null ? new TextBlock { Text = "View not found: " + name } : (Control)Activator.CreateInstance(type)!;
    }

    public bool Match(object? data) => data is PageViewModel;
}
