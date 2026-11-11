namespace NetmonEtw.Core;

public sealed class Options
{
    public int IntervalMs { get; set; } = 1000;
    public string? Pipe { get; set; }
    public bool Once { get; set; }
    public bool NoEtw { get; set; }
    public bool Help { get; set; }
    public bool Version { get; set; }
    public bool ExitOnStdinEof { get; set; }
    public string SessionName { get; set; } = "netmon-etw";

    public const string Usage =
@"netmon-etw - read-only per-service network bytes from ETW kernel TCP/IP events

usage: netmon-etw.exe [--interval-ms N] [--pipe NAME] [--once] [--no-etw] [--session NAME]
                      [--exit-on-stdin-eof]

  --interval-ms N  snapshot period (250..60000, default 1000)
  --pipe NAME      write JSON lines to \\.\pipe\NAME (current user only) instead of stdout
  --once           wait one interval, print one snapshot, exit
  --no-etw         service list only (no kernel session; works without admin)
  --session NAME   ETW session name (default netmon-etw)
  --exit-on-stdin-eof  stop cleanly (closing the ETW session) when stdin closes;
                   used by netmon_win.py so the kernel session never outlives the core

Output: one JSON object per line (schema netmon-etw/1). Needs Administrator for ETW;
without it, snapshots still list services but bytes are null and etw.error explains why.";

    public static Options Parse(IReadOnlyList<string> args)
    {
        var o = new Options();
        for (int i = 0; i < args.Count; i++)
        {
            string a = args[i];
            string Next() => i + 1 < args.Count ? args[++i] : throw new ArgumentException($"{a} needs a value");
            switch (a)
            {
                case "--interval-ms":
                    if (!int.TryParse(Next(), out var ms) || ms < 250 || ms > 60000)
                        throw new ArgumentException("--interval-ms must be 250..60000");
                    o.IntervalMs = ms; break;
                case "--pipe":
                    var p = Next();
                    if (p.Length == 0 || p.Length > 200 || p.Any(c => c == '\\' || c == '/' || char.IsControl(c)))
                        throw new ArgumentException("--pipe takes a bare pipe name, e.g. netmon-etw");
                    o.Pipe = p; break;
                case "--session":
                    var s = Next();
                    if (s.Length == 0 || s.Length > 100) throw new ArgumentException("bad --session");
                    o.SessionName = s; break;
                case "--once": o.Once = true; break;
                case "--no-etw": o.NoEtw = true; break;
                case "--exit-on-stdin-eof": o.ExitOnStdinEof = true; break;
                case "-h": case "--help": case "/?": o.Help = true; break;
                case "--version": o.Version = true; break;
                default: throw new ArgumentException($"unknown argument: {a}");
            }
        }
        return o;
    }
}
