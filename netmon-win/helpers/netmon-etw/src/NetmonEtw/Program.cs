using System.Diagnostics;
using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using NetmonEtw;
using NetmonEtw.Core;

const string Version = "1.0.0";
Options opt;
try { opt = Options.Parse(args); }
catch (ArgumentException e) { Console.Error.WriteLine(e.Message); Console.Error.WriteLine(Options.Usage); return 2; }
if (opt.Help) { Console.WriteLine(Options.Usage); return 0; }
if (opt.Version) { Console.WriteLine("netmon-etw " + Version); return 0; }
if (!OperatingSystem.IsWindows()) { Console.Error.WriteLine("netmon-etw runs on Windows only"); return 3; }

bool admin = new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);
var table = new ByteTable();
using var etw = new EtwCollector(opt.SessionName, table);
if (!opt.NoEtw) etw.Start();
if (!admin) Console.Error.WriteLine("netmon-etw: not running as Administrator: services only, bytes = null");

using var cts = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };
if (opt.ExitOnStdinEof)
{
    // Parent (netmon_win.py) holds our stdin open; when it exits or closes it we stop cleanly,
    // which disposes the TraceEventSession (StopOnDispose) instead of leaking a kernel logger.
    new Thread(() =>
    {
        try { using var stdin = Console.OpenStandardInput(); var b = new byte[256]; while (stdin.Read(b, 0, b.Length) > 0) { } }
        catch { /* treat as EOF */ }
        cts.Cancel();
    }) { IsBackground = true, Name = "stdin-eof" }.Start();
}
AppDomain.CurrentDomain.ProcessExit += (_, _) => { cts.Cancel(); etw.Dispose(); };

TextWriter output;
NamedPipeServerStream? pipe = null;
if (opt.Pipe != null)
{
    // Pipe readable/writable by the current user only (default DACL would allow Everyone to read).
    var sec = new PipeSecurity();
    sec.AddAccessRule(new PipeAccessRule(WindowsIdentity.GetCurrent().User!, PipeAccessRights.FullControl, AccessControlType.Allow));
    pipe = NamedPipeServerStreamAcl.Create(opt.Pipe, PipeDirection.Out, 1, PipeTransmissionMode.Byte,
                                           PipeOptions.Asynchronous, 0, 0, sec);
    Console.Error.WriteLine($@"netmon-etw: waiting for a reader on \\.\pipe\{opt.Pipe}");
    await pipe.WaitForConnectionAsync(cts.Token);
    output = new StreamWriter(pipe, new UTF8Encoding(false)) { AutoFlush = true, NewLine = "\n" };
}
else
{
    output = new StreamWriter(Console.OpenStandardOutput(), new UTF8Encoding(false)) { AutoFlush = true, NewLine = "\n" };
}

var names = new Dictionary<int, string>();
string ProcName(int pid)
{
    if (pid == 0) return "Idle";
    if (pid == 4) return "System";
    if (names.TryGetValue(pid, out var n)) return n;
    try { using var p = Process.GetProcessById(pid); n = p.ProcessName + ".exe"; }
    catch { n = "pid " + pid; }
    return names[pid] = n;
}

long seq = 0;
try
{
    while (!cts.IsCancellationRequested)
    {
        try { await Task.Delay(opt.IntervalMs, cts.Token); } catch (TaskCanceledException) { break; }
        names.Clear();
        List<ServiceInfo> services; string? scmErr = null;
        try { services = Scm.Enumerate(); }
        catch (Exception e) { services = new(); scmErr = e.Message; }
        var bytes = etw.Active ? table.Read() : null;
        var (groups, rows, nonSvc, top) = Attribution.Build(services, bytes, ProcName);
        var snap = new Snapshot
        {
            Version = Version, Seq = ++seq, Ts = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() / 1000.0, Admin = admin,
            Etw = new EtwStatus
            {
                Active = etw.Active, Session = etw.SessionName, Events = etw.Events, EventsLost = etw.EventsLost,
                Error = opt.NoEtw ? "disabled with --no-etw" : etw.Error,
            },
            ScmError = scmErr, Services = rows, Groups = groups,
            NonService = bytes == null ? new ProcessBytes { Pid = -1, Process = "(non-service processes)" } : nonSvc,
            TopNonService = top,
        };
        try { output.WriteLine(Json.Line(snap)); }
        catch (IOException) { break; } // reader went away
        if (opt.Once) break;
    }
}
finally
{
    etw.Dispose();
    pipe?.Dispose();
}
return 0;
