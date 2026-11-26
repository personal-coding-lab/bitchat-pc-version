namespace BitchatWindows.Services;

/// <summary>Small local-only startup trace for Bluetooth transport diagnosis.</summary>
internal static class DiagnosticLog
{
    private static readonly string Path = System.IO.Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "BitchatWindows", "diagnostics.log");

    internal static void Write(string message)
    {
        try
        {
            System.IO.Directory.CreateDirectory(System.IO.Path.GetDirectoryName(Path)!);
            System.IO.File.AppendAllText(Path, $"{DateTimeOffset.Now:O} {message}{Environment.NewLine}");
        }
        catch
        {
            // Diagnostics must never prevent the transport from starting.
        }
    }
}
