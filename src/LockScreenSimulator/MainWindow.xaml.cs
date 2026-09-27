using System.Windows;
using System.Windows.Threading;

namespace LockScreenSimulator;

public partial class MainWindow : Window
{
    private readonly DispatcherTimer _timer = new() { Interval = TimeSpan.FromSeconds(1) };
    private readonly ScenarioViewModel _viewModel;

    public MainWindow(ScenarioViewModel viewModel)
    {
        InitializeComponent();
        _viewModel = viewModel;
        DataContext = viewModel;
        _timer.Tick += (_, _) => _viewModel.Tick();
        _timer.Start();
        Closed += (_, _) => _timer.Stop();
    }

    private void Exit_Click(object sender, RoutedEventArgs e) => Close();
}
