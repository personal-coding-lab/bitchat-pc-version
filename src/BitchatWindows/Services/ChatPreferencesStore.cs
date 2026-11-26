using System.Text.Json;
using System.IO;

namespace BitchatWindows.Services;

/// <summary>Small, local-only preferences store. It never contains message text or keys.</summary>
public sealed class ChatPreferencesStore
{
    private readonly string _path = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "BitchatWindows",
        "chat-preferences.json");

    public ChatPreferences Load()
    {
        try
        {
            if (!File.Exists(_path)) return new ChatPreferences();
            return JsonSerializer.Deserialize<ChatPreferences>(File.ReadAllText(_path)) ?? new ChatPreferences();
        }
        catch (Exception ex)
        {
            DiagnosticLog.Write($"Chat preferences could not be loaded: {ex.Message}");
            return new ChatPreferences();
        }
    }

    public void Save(ChatPreferences preferences)
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
            var temporary = _path + ".tmp";
            File.WriteAllText(temporary, JsonSerializer.Serialize(preferences, new JsonSerializerOptions { WriteIndented = true }));
            File.Move(temporary, _path, true);
        }
        catch (Exception ex)
        {
            DiagnosticLog.Write($"Chat preferences could not be saved: {ex.Message}");
        }
    }
}

public sealed class ChatPreferences
{
    public string Nickname { get; set; } = "Windows";
    public string ActiveRoom { get; set; } = "bluetooth";
    public HashSet<string> BlockedFingerprints { get; set; } = new(StringComparer.OrdinalIgnoreCase);
    public HashSet<string> BlockedRoutingIds { get; set; } = new(StringComparer.OrdinalIgnoreCase);
}
