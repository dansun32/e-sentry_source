using System.Collections.Concurrent;

namespace NetmonEtw.Core;

/// <summary>Thread-safe per-PID byte accumulator fed from the ETW callback thread.</summary>
public sealed class ByteTable
{
    private sealed class Cell { public long In; public long Out; }
    private readonly ConcurrentDictionary<int, Cell> _cells = new();

    public void Add(int pid, long inBytes, long outBytes)
    {
        if (pid < 0 || (inBytes <= 0 && outBytes <= 0)) return;
        var c = _cells.GetOrAdd(pid, _ => new Cell());
        if (inBytes > 0) Interlocked.Add(ref c.In, inBytes);
        if (outBytes > 0) Interlocked.Add(ref c.Out, outBytes);
    }

    /// <summary>Process exited: drop its counters so a reused PID starts from zero.</summary>
    public void Forget(int pid) => _cells.TryRemove(pid, out _);

    public Dictionary<int, (long In, long Out)> Read()
    {
        var d = new Dictionary<int, (long, long)>();
        foreach (var kv in _cells) d[kv.Key] = (Interlocked.Read(ref kv.Value.In), Interlocked.Read(ref kv.Value.Out));
        return d;
    }
}
