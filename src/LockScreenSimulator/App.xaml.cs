using System.Windows;

namespace LockScreenSimulator;

public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        if (e.Args.Length != 1)
        {
            MessageBox.Show("Usage: LockScreenSimulator.exe <synthetic-disk.img>", "Forensic Lab", MessageBoxButton.OK, MessageBoxImage.Information);
            Shutdown(64);
            return;
        }
        try
        {
            var sector = SectorMessageReader.Read(e.Args[0]);
            new MainWindow(new ScenarioViewModel(sector.ScenarioId, sector.Message, TimeSpan.FromMinutes(30))).Show();
        }
        catch (Exception ex)
        {
            MessageBox.Show(ex.Message, "Invalid laboratory artifact", MessageBoxButton.OK, MessageBoxImage.Error);
            Shutdown(10);
        }
    }
}
