using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using Microsoft.Diagnostics.Tracing.Session;
using NetmonEtw.Core;

namespace NetmonEtw;

/// <summary>
/// Kernel NetworkTCPIP session (the source Resource Monitor uses). Each TcpIp/UdpIp Send/Recv
/// event carries the owning PID and the payload size; we sum them per PID. Process-stop events
/// clear a PID so a reused PID starts from zero. Read-only: nothing is changed on the system.
/// Requires Administrator (or Performance Log Users with kernel-logger rights). Windows 8+ allows
/// a privately named kernel session, so we do not take over "NT Kernel Logger".
/// </summary>
internal sealed class EtwCollector : IDisposable
{
    private readonly ByteTable _table;
    private TraceEventSession? _session;
    private Thread? _thread;
    private long _events;
    public string SessionName { get; }
    public string? Error { get; private set; }
    public bool Active => _session != null && Error == null;
    public long Events => Interlocked.Read(ref _events);
    public long EventsLost => _session?.EventsLost ?? 0;

    public EtwCollector(string sessionName, ByteTable table) { SessionName = sessionName; _table = table; }

    public void Start()
    {
        try
        {
            if (TraceEventSession.IsElevated() != true)
            {
                Error = "not elevated: run as Administrator for ETW kernel TCP/IP bytes";
                return;
            }
            _session = new TraceEventSession(SessionName) { StopOnDispose = true };
            _session.EnableKernelProvider(KernelTraceEventParser.Keywords.NetworkTCPIP | KernelTraceEventParser.Keywords.Process);
            var k = _session.Source.Kernel;
            // ProcessID on these events is taken from the event payload (the sending/receiving process).
            k.TcpIpRecv += d => Add(d.ProcessID, d.size, 0);
            k.TcpIpSend += d => Add(d.ProcessID, 0, d.size);
            k.TcpIpRecvIPV6 += d => Add(d.ProcessID, d.size, 0);
            k.TcpIpSendIPV6 += d => Add(d.ProcessID, 0, d.size);
            k.UdpIpRecv += d => Add(d.ProcessID, d.size, 0);
            k.UdpIpSend += d => Add(d.ProcessID, 0, d.size);
            k.UdpIpRecvIPV6 += d => Add(d.ProcessID, d.size, 0);
            k.UdpIpSendIPV6 += d => Add(d.ProcessID, 0, d.size);
            k.ProcessStop += d => _table.Forget(d.ProcessID);
            _thread = new Thread(() =>
            {
                try { _session.Source.Process(); }
                catch (Exception e) { Error = "ETW processing stopped: " + e.Message; }
            }) { IsBackground = true, Name = "etw" };
            _thread.Start();
        }
        catch (Exception e)
        {
            Error = $"ETW session failed: {e.GetType().Name}: {e.Message}";
            _session?.Dispose();
            _session = null;
        }
    }

    private void Add(int pid, int inBytes, int outBytes)
    {
        Interlocked.Increment(ref _events);
        _table.Add(pid, inBytes, outBytes);
    }

    public void Dispose()
    {
        try { _session?.Dispose(); } catch { /* shutting down */ }
    }
}
