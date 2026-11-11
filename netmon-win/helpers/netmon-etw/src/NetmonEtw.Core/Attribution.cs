namespace NetmonEtw.Core;

/// <summary>
/// Maps ETW per-process bytes onto services.
///
/// ETW kernel TCP/IP events carry a process id, not a service name. A process hosting exactly
/// one service gets "exclusive" attribution. When several services share one svchost.exe the
/// kernel cannot tell which service moved the bytes, so they are reported once for the whole
/// group ("shared-process") and never divided or duplicated. On Windows 10 1703+ with more than
/// 3.5 GB RAM most svchost services run in their own process, so most rows are exclusive.
/// </summary>
public static class Attribution
{
    public static (List<ServiceGroup> Groups, List<ServiceRow> Rows, ProcessBytes NonService, List<ProcessBytes> TopNonService)
        Build(IReadOnlyList<ServiceInfo> services, IReadOnlyDictionary<int, (long In, long Out)>? bytes,
              Func<int, string> processName, int topN = 5)
    {
        var byPid = services.Where(s => s.Pid > 0)
                            .GroupBy(s => s.Pid)
                            .OrderBy(g => g.Key);
        var groups = new List<ServiceGroup>();
        var groupOfPid = new Dictionary<int, string>();
        foreach (var g in byPid)
        {
            var names = g.Select(s => s.Name).OrderBy(n => n, StringComparer.OrdinalIgnoreCase).ToList();
            long? i = null, o = null;
            if (bytes != null)
            {
                bytes.TryGetValue(g.Key, out var b);
                i = b.In; o = b.Out;
            }
            var id = "pid:" + g.Key;
            groupOfPid[g.Key] = id;
            groups.Add(new ServiceGroup
            {
                Id = id, Pid = g.Key, Process = processName(g.Key), Services = names,
                Attribution = names.Count == 1 ? "exclusive" : "shared-process",
                InBytes = i, OutBytes = o,
            });
        }

        var rows = services.OrderBy(s => s.Name, StringComparer.OrdinalIgnoreCase).Select(s => new ServiceRow
        {
            Name = s.Name, DisplayName = s.DisplayName, State = s.State, StartType = s.StartType, Pid = s.Pid,
            Group = s.Pid > 0 && groupOfPid.TryGetValue(s.Pid, out var gid) ? gid : null,
        }).ToList();

        long ni = 0, no = 0;
        var others = new List<ProcessBytes>();
        if (bytes != null)
        {
            foreach (var kv in bytes)
            {
                if (groupOfPid.ContainsKey(kv.Key)) continue;
                ni += kv.Value.In; no += kv.Value.Out;
                others.Add(new ProcessBytes { Pid = kv.Key, InBytes = kv.Value.In, OutBytes = kv.Value.Out });
            }
        }
        var top = others.OrderByDescending(p => p.InBytes + p.OutBytes).ThenBy(p => p.Pid).Take(topN)
                        .Select(p => new ProcessBytes { Pid = p.Pid, Process = processName(p.Pid), InBytes = p.InBytes, OutBytes = p.OutBytes })
                        .ToList();
        return (groups, rows, new ProcessBytes { Pid = -1, Process = "(non-service processes)", InBytes = ni, OutBytes = no }, top);
    }

    /// <summary>SCM numeric codes to stable lower-case strings.</summary>
    public static string StateName(uint s) => s switch
    {
        1 => "stopped", 2 => "start_pending", 3 => "stop_pending", 4 => "running",
        5 => "continue_pending", 6 => "pause_pending", 7 => "paused", _ => "unknown",
    };

    public static string StartTypeName(uint t) => t switch
    {
        0 => "boot", 1 => "system", 2 => "auto", 3 => "demand", 4 => "disabled", _ => "unknown",
    };
}
