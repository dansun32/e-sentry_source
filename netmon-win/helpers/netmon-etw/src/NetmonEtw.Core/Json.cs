using System.Text.Encodings.Web;
using System.Text.Json;

namespace NetmonEtw.Core;

public static class Json
{
    private static readonly JsonSerializerOptions Opts = new()
    {
        WriteIndented = false,
        // Escape <, >, & etc. too: the data is shown in a web page (the page escapes again).
        Encoder = JavaScriptEncoder.Default,
    };

    /// <summary>One compact line, no embedded newlines (JSON-lines framing).</summary>
    public static string Line<T>(T value) => JsonSerializer.Serialize(value, Opts);
}
