using System.Text.Json;
using NetmonEtw.Core;
using Xunit;

public class CoreTests
{
    static readonly List<ServiceInfo> Svcs = new()
    {
        new("Dnscache", "DNS Client", "running", "auto", 1200, true),
        new("NlaSvc", "Network Location Awareness", "running", "auto", 1200, true),
        new("PIA", "Private Internet Access Service", "running", "auto", 3300, false),
        new("Spooler", "Print Spooler", "stopped", "demand", 0, false),
    };

    static string Name(int pid) => pid switch { 1200 => "svchost.exe", 3300 => "pia-service.exe", 900 => "chrome.exe", _ => "pid " + pid };

    [Fact]
    public void SharedSvchostIsOneGroupAndBytesAreNotSplit()
    {
        var bytes = new Dictionary<int, (long, long)> { [1200] = (1000, 500), [3300] = (70, 30), [900] = (9, 1) };
        var (groups, rows, non, top) = Attribution.Build(Svcs, bytes, Name);
        Assert.Equal(2, groups.Count);
        var g = groups.Single(x => x.Pid == 1200);
        Assert.Equal("shared-process", g.Attribution);
        Assert.Equal(new[] { "Dnscache", "NlaSvc" }, g.Services);
        Assert.Equal(1000, g.InBytes); Assert.Equal(500, g.OutBytes);
        Assert.Equal("exclusive", groups.Single(x => x.Pid == 3300).Attribution);
        Assert.Null(rows.Single(r => r.Name == "Spooler").Group);
        Assert.Equal("pid:1200", rows.Single(r => r.Name == "NlaSvc").Group);
        Assert.Equal(9, non.InBytes); Assert.Equal(1, non.OutBytes);
        Assert.Equal("chrome.exe", Assert.Single(top).Process);
    }

    [Fact]
    public void NoEtwMeansNullBytesNotZero()
    {
        var (groups, _, non, top) = Attribution.Build(Svcs, null, Name);
        Assert.All(groups, g => { Assert.Null(g.InBytes); Assert.Null(g.OutBytes); });
        Assert.Empty(top);
        Assert.Equal(0, non.InBytes);
    }

    [Fact]
    public void ServiceSeenByEtwWithoutTrafficGetsZero()
    {
        var (groups, _, _, _) = Attribution.Build(Svcs, new Dictionary<int, (long, long)>(), Name);
        Assert.All(groups, g => Assert.Equal(0, g.InBytes));
    }

    [Fact]
    public void ByteTableAccumulatesAndForgets()
    {
        var t = new ByteTable();
        t.Add(5, 10, 0); t.Add(5, 0, 7); t.Add(5, -3, 0); t.Add(6, 1, 1);
        Assert.Equal((10L, 7L), t.Read()[5]);
        t.Forget(5);
        Assert.False(t.Read().ContainsKey(5));
        Parallel.For(0, 1000, _ => t.Add(6, 1, 2));
        Assert.Equal((1001L, 2001L), t.Read()[6]);
    }

    [Fact]
    public void JsonLineShapeAndEscaping()
    {
        var (groups, rows, non, top) = Attribution.Build(
            new List<ServiceInfo> { new("<b>x</b>", "a\nb", "running", "auto", 7, false) },
            new Dictionary<int, (long, long)> { [7] = (1, 2) }, _ => "evil<script>.exe");
        var line = Json.Line(new Snapshot { Version = "t", Seq = 1, Ts = 1.5, Admin = true, Services = rows, Groups = groups, NonService = non, TopNonService = top });
        Assert.DoesNotContain("\n", line);
        Assert.DoesNotContain("<", line);
        using var doc = JsonDocument.Parse(line);
        var r = doc.RootElement;
        foreach (var k in new[] { "schema", "type", "seq", "ts", "admin", "etw", "services", "groups", "nonService", "topNonService" })
            Assert.True(r.TryGetProperty(k, out _), k);
        Assert.Equal("netmon-etw/1", r.GetProperty("schema").GetString());
        Assert.Equal("<b>x</b>", r.GetProperty("services")[0].GetProperty("name").GetString());
        Assert.Equal(2, r.GetProperty("groups")[0].GetProperty("outBytes").GetInt64());
    }

    [Theory]
    [InlineData(1u, "stopped")] [InlineData(4u, "running")] [InlineData(99u, "unknown")]
    public void StateNames(uint code, string name) => Assert.Equal(name, Attribution.StateName(code));

    [Fact]
    public void OptionsParse()
    {
        var o = Options.Parse(new[] { "--interval-ms", "500", "--pipe", "netmon-etw", "--once" });
        Assert.Equal(500, o.IntervalMs); Assert.Equal("netmon-etw", o.Pipe); Assert.True(o.Once);
        Assert.Throws<ArgumentException>(() => Options.Parse(new[] { "--interval-ms", "5" }));
        Assert.Throws<ArgumentException>(() => Options.Parse(new[] { "--pipe", @"..\x" }));
        Assert.Throws<ArgumentException>(() => Options.Parse(new[] { "--bogus" }));
        Assert.True(Options.Parse(new[] { "--exit-on-stdin-eof" }).ExitOnStdinEof);
    }
}
