using System.Text.Json.Serialization;

namespace NetmonEtw.Core;

/// <summary>One Windows service as reported by the Service Control Manager.</summary>
public sealed record ServiceInfo(
    string Name,
    string DisplayName,
    string State,       // running, stopped, start_pending, ...
    string StartType,   // auto, demand, disabled, boot, system, unknown
    int Pid,            // 0 when not running
    bool SharedProcess  // SERVICE_WIN32_SHARE_PROCESS type bit
);

/// <summary>Services that live in one process, with the bytes ETW saw for that process.</summary>
public sealed class ServiceGroup
{
    [JsonPropertyName("id")] public string Id { get; init; } = "";
    [JsonPropertyName("pid")] public int Pid { get; init; }
    [JsonPropertyName("process")] public string Process { get; init; } = "";
    [JsonPropertyName("services")] public List<string> Services { get; init; } = new();
    /// <summary>"exclusive" = one service in the process, bytes are that service's.
    /// "shared-process" = several services share the process (svchost); bytes belong to the
    /// process as a whole and are NOT split between the members.</summary>
    [JsonPropertyName("attribution")] public string Attribution { get; init; } = "exclusive";
    [JsonPropertyName("inBytes")] public long? InBytes { get; init; }
    [JsonPropertyName("outBytes")] public long? OutBytes { get; init; }
}

public sealed class ServiceRow
{
    [JsonPropertyName("name")] public string Name { get; init; } = "";
    [JsonPropertyName("displayName")] public string DisplayName { get; init; } = "";
    [JsonPropertyName("state")] public string State { get; init; } = "";
    [JsonPropertyName("startType")] public string StartType { get; init; } = "";
    [JsonPropertyName("pid")] public int Pid { get; init; }
    [JsonPropertyName("group")] public string? Group { get; init; }
}

public sealed class ProcessBytes
{
    [JsonPropertyName("pid")] public int Pid { get; init; }
    [JsonPropertyName("process")] public string Process { get; init; } = "";
    [JsonPropertyName("inBytes")] public long InBytes { get; init; }
    [JsonPropertyName("outBytes")] public long OutBytes { get; init; }
}

public sealed class EtwStatus
{
    [JsonPropertyName("active")] public bool Active { get; init; }
    [JsonPropertyName("session")] public string Session { get; init; } = "";
    [JsonPropertyName("error")] public string? Error { get; init; }
    [JsonPropertyName("events")] public long Events { get; init; }
    [JsonPropertyName("eventsLost")] public long EventsLost { get; init; }
}

/// <summary>One JSON line on stdout / the pipe. Byte counters are cumulative since helper start.</summary>
public sealed class Snapshot
{
    [JsonPropertyName("schema")] public string Schema { get; init; } = "netmon-etw/1";
    [JsonPropertyName("type")] public string Type { get; init; } = "snapshot";
    [JsonPropertyName("version")] public string Version { get; init; } = "";
    [JsonPropertyName("seq")] public long Seq { get; init; }
    [JsonPropertyName("ts")] public double Ts { get; init; }
    [JsonPropertyName("admin")] public bool Admin { get; init; }
    [JsonPropertyName("etw")] public EtwStatus Etw { get; init; } = new();
    [JsonPropertyName("scmError")] public string? ScmError { get; init; }
    [JsonPropertyName("services")] public List<ServiceRow> Services { get; init; } = new();
    [JsonPropertyName("groups")] public List<ServiceGroup> Groups { get; init; } = new();
    /// <summary>Bytes of processes that host no service (browsers etc.), summed.</summary>
    [JsonPropertyName("nonService")] public ProcessBytes NonService { get; init; } = new();
    [JsonPropertyName("topNonService")] public List<ProcessBytes> TopNonService { get; init; } = new();
}
