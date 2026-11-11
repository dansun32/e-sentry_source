"""Derive page/index.html (Windows) from the live page with exact, checked replacements."""
import sys
src = open(sys.argv[1], encoding="utf-8").read()
s = src
def rep(old, new, count=1):
    global s
    n = s.count(old)
    if n != count:
        raise SystemExit("anchor found %d times (want %d): %r" % (n, count, old[:80]))
    s = s.replace(old, new)

rep("<title>systemd-netmon - Terminal Network Monitor</title>", "<title>netmon-win - Terminal Network Monitor</title>")
rep("</i> systemd-netmon v1.4.0", "</i> netmon-win v1.4.0")
rep('font-medium">LIVE D-BUS POLLING</span>', 'font-medium">LIVE ETW POLLING</span>')
rep('hidden md:inline">Mint 21.3 / Linux 6.5.0-35-generic</span>', 'hidden md:inline">Windows</span>')
rep('placeholder="Filter units... [ / ]"', 'placeholder="Filter services... [ / ]"')
rep("<span>DBUS INFO</span>", "<span>ETW INFO</span>")
rep("<!-- D-Bus Info Drawer Toggle -->", "<!-- ETW Info Drawer Toggle -->")
rep(">Systemd Total Ingress</span>", ">Services Total Ingress</span>")
rep(">Systemd Total Egress</span>", ">Services Total Egress</span>")
rep(">Active Monitored Units</span>", ">ETW Monitored Services</span>")
rep(">Raw Sockets Bypass</span>", ">Capture / Raw / WFP</span>")
rep('id="raw-sockets-count" class="text-amber-400 font-bold text-sm">0 sockets active</span>\n        </div>\n    </div>\n',
    'id="raw-sockets-count" class="text-amber-400 font-bold text-sm">0 capture</span>\n        </div>\n    </div>\n'
    '\n    <!-- Degraded-mode banner (hidden when everything is available) -->\n'
    '    <div id="helper-banner" class="hidden bg-amber-950/40 border-b border-amber-800/40 px-4 py-1 text-[11px] text-amber-300 font-mono truncate"></div>\n')
rep("<!-- TOP SECTION: SYSTEMD NETWORK SERVICES -->", "<!-- TOP SECTION: WINDOWS SERVICES -->")
rep("<span>SYSTEMD NETWORK SERVICES (SORTED TOP-DOWN BY THROUGHPUT)</span>", "<span>WINDOWS SERVICES (SORTED TOP-DOWN BY THROUGHPUT)</span>")
rep('Targeting <code class="text-slate-400 bg-slate-800 px-1 py-0.5 rounded">IPAccounting=yes</code> via D-Bus',
    'Targeting <code class="text-slate-400 bg-slate-800 px-1 py-0.5 rounded">ETW kernel TCP/IP</code> via netmon-etw')
rep("<span>Service Unit Name</span>", "<span>Service Name</span>")
rep("<!-- BOTTOM SECTION: RAW / UNGOVERNED SOCKETS -->", "<!-- BOTTOM SECTION: CAPTURE / RAW / WFP -->")
rep("<span>RAW / PACKET SOCKETS PANEL (BYPASSING /etc/hosts.deny)</span>", "<span>CAPTURE / RAW / WFP PANEL (BELOW THE NORMAL STACK)</span>")
rep('''                <div class="text-[11px] text-slate-400 bg-amber-950/40 border border-amber-800/40 px-2 py-0.5 rounded">
                    Source: <code class="text-amber-300">/proc/net/raw</code> & <code class="text-amber-300">/proc/net/packet</code>
                </div>''',
'''                <div class="flex items-center gap-2">
                    <button id="btn-wfp" onclick="toggleWfp()" title="Show/hide WFP filter and callout rows [ W ]" class="text-[11px] text-amber-300 bg-amber-950/40 hover:bg-amber-900/40 border border-amber-800/40 px-2 py-0.5 rounded">WFP: ON</button>
                    <div class="text-[11px] text-slate-400 bg-amber-950/40 border border-amber-800/40 px-2 py-0.5 rounded">
                        Source: <code class="text-amber-300">Npcap</code> & <code class="text-amber-300">WFP (Fwpm*)</code>
                    </div>
                </div>''')
rep('<div class="col-span-2 sm:col-span-1">Inode</div>', '<div class="col-span-2 sm:col-span-1">Kind</div>')
rep('<div class="col-span-3 sm:col-span-3">Process Name</div>', '<div class="col-span-3 sm:col-span-3">Process / Provider</div>')
rep('<div class="col-span-2 sm:col-span-2">Protocol / Type</div>', '<div class="col-span-2 sm:col-span-2">Source / Layer</div>')
rep('<div class="col-span-3 sm:col-span-2 text-right" title="No per-socket packet counters exist for raw/packet sockets; showing the kernel drop counter rate">Drop Rate</div>',
    '<div class="col-span-3 sm:col-span-2 text-right" title="module / handle / driver state / WFP action">Detail</div>')
rep('<div class="hidden sm:block sm:col-span-3 text-right" title="raw/raw6: cumulative kernel drops; packet: receive buffer bytes (Rmem)">Drops / Rmem</div>',
    '<div class="hidden sm:block sm:col-span-3 text-right" title="modules, devices, adapters, filters or callouts">Count</div>')
rep('''            <span><kbd class="bg-slate-800 text-slate-200 px-1.5 py-0.5 rounded border border-slate-700">R</kbd> Reset Stats</span>''',
'''            <span><kbd class="bg-slate-800 text-slate-200 px-1.5 py-0.5 rounded border border-slate-700">R</kbd> Reset Stats</span>
            <span><kbd class="bg-slate-800 text-slate-200 px-1.5 py-0.5 rounded border border-slate-700">W</kbd> WFP Rows</span>''')
rep('D-Bus: <span class="text-cyan-400">org.freedesktop.systemd1</span>', 'ETW: <span class="text-cyan-400">Microsoft-Windows-Kernel-Network</span>')
rep("<!-- SLIDE-OVER DRAWER FOR DBUS & SYSTEMD ACCOUNTS DOCS -->", "<!-- SLIDE-OVER DRAWER FOR ETW / WFP / NPCAP DOCS -->")
rep('<span class="text-sm">systemd D-Bus & IPAccounting Reference</span>', '<span class="text-sm">ETW, WFP &amp; Npcap Reference</span>')

# Drawer body: replace the four sections, keep the container and styling classes.
a = s.index('            <div>\n                <h3 class="text-sm font-bold text-cyan-400 font-mono mb-1">1. Querying Systemd Units via D-Bus</h3>')
b = s.index('    <!-- Application Script Engine -->')
drawer = '''            <div>
                <h3 class="text-sm font-bold text-cyan-400 font-mono mb-1">1. Per-Service Bytes from ETW</h3>
                <p class="text-xs text-slate-400 mb-2"><code class="text-emerald-300 font-mono">netmon-etw.exe</code> opens a private kernel ETW session with the <code class="text-emerald-300 font-mono">NetworkTCPIP</code> keyword (the source Resource Monitor uses) and sums the payload size of every TCP/UDP send and receive per process.</p>
                <div class="bg-slate-950 p-3 rounded border border-slate-800 font-mono text-[11px] text-slate-300 overflow-x-auto">
                    <pre><span class="text-slate-500"># Same data, by hand (elevated prompt):</span>
logman start "NT Kernel Logger" -p "Windows Kernel Trace" (net) -o net.etl -ets
logman stop "NT Kernel Logger" -ets

<span class="text-slate-500"># Leftover session after a crash? Stop it:</span>
logman stop netmon-etw -ets</pre>
                </div>
            </div>

            <div>
                <h3 class="text-sm font-bold text-cyan-400 font-mono mb-1">2. Kernel Events Counted</h3>
                <ul class="list-disc pl-5 space-y-1 text-xs text-slate-300">
                    <li><code class="text-emerald-400 font-mono">TcpIp/Recv</code>, <code class="text-emerald-400 font-mono">UdpIp/Recv</code> (+IPv6): inbound bytes per PID.</li>
                    <li><code class="text-cyan-400 font-mono">TcpIp/Send</code>, <code class="text-cyan-400 font-mono">UdpIp/Send</code> (+IPv6): outbound bytes per PID.</li>
                    <li><code class="text-emerald-400 font-mono">Process/Stop</code>: clears a PID so a reused PID starts from zero.</li>
                    <li>PID &rarr; services via the SCM (<code class="text-cyan-400 font-mono">EnumServicesStatusEx</code>). Services sharing one <code class="text-cyan-400 font-mono">svchost.exe</code> appear as one row (<em>Name +N</em>); its bytes belong to the whole process and are not split.</li>
                </ul>
            </div>

            <div>
                <h3 class="text-sm font-bold text-cyan-400 font-mono mb-1">3. TraceEvent Snippet (C#)</h3>
                <div class="bg-slate-950 p-3 rounded border border-slate-800 font-mono text-[11px] text-slate-300 overflow-x-auto">
                    <pre><span class="text-purple-400">using var</span> session = <span class="text-purple-400">new</span> TraceEventSession(<span class="text-emerald-300">"netmon-etw"</span>);
session.EnableKernelProvider(
    KernelTraceEventParser.Keywords.NetworkTCPIP |
    KernelTraceEventParser.Keywords.Process);

session.Source.Kernel.TcpIpRecv += d =&gt; Add(d.ProcessID, d.size, 0);
session.Source.Kernel.TcpIpSend += d =&gt; Add(d.ProcessID, 0, d.size);
session.Source.Process();   <span class="text-slate-500">// needs Administrator</span></pre>
                </div>
            </div>

            <div>
                <h3 class="text-sm font-bold text-amber-400 font-mono mb-1">4. Below the Normal Stack: Npcap, Raw Sockets, WFP</h3>
                <p class="text-xs text-slate-400 leading-normal">
                    Windows has no public list of raw sockets (<code class="text-amber-300">GetExtendedTcpTable</code>/<code class="text-amber-300">UdpTable</code> cover TCP and UDP only), so this panel shows who can see or filter packets below sockets instead:
                    processes that loaded Npcap/WinPcap (<code class="text-amber-300">wpcap.dll</code>, <code class="text-amber-300">Packet.dll</code>),
                    optionally processes holding <code class="text-amber-300">\\Device\\NPCAP</code> handles (<code class="text-amber-300">--handles</code>),
                    and the Windows Filtering Platform filters and callouts registered by firewalls and VPN killswitches (such as PIA), grouped by provider, layer and action.
                </p>
            </div>
        </div>
    </div>

'''
s = s[:a] + drawer + s[b:]

# ---------------------------------------------------------------- script
rep("statusText.textContent = 'LIVE D-BUS POLLING';\n                setHelperStatus(helperOk);",
    "statusText.textContent = 'LIVE ETW POLLING';\n                setHelperStatus(helperOk);")
rep("""        let liveTotals = { ingressRate: 0, egressRate: 0, running: 0, monitored: 0, sockets: 0 };
        let baseline = {};      // client-side "Reset Stats" baselines: unit -> bytes, inode -> drops
        let lastDrops = {};     // inode -> {drops, t} for drop-rate deltas
""", """        let liveTotals = { ingressRate: 0, egressRate: 0, running: 0, monitored: 0, sockets: 0 };
        let baseline = {};      // client-side "Reset Stats" baselines: service row id -> bytes
        let showWfp = true;     // W key / panel button
        let liveMode = 'etw';
""")
rep("""                } else if (e.key.toLowerCase() === 'r') {
                    resetStats();
                }""", """                } else if (e.key.toLowerCase() === 'r') {
                    resetStats();
                } else if (e.key.toLowerCase() === 'w') {
                    toggleWfp();
                }""")
rep("""                if (e.key === ' ') {
                    e.preventDefault();
                    togglePause();""", """                if (e.target && e.target.id === 'search-input') {
                    if (e.key === 'Escape') e.target.blur();
                    return;  // typing in the filter box (space / r / w are text there)
                } else if (e.key === ' ') {
                    e.preventDefault();
                    togglePause();""")
rep("""            servicesData.forEach(s => {
                baseline['u:' + s.name] = { ingress: s.rawIngress || 0, egress: s.rawEgress || 0 };""",
    """            servicesData.forEach(s => {
                baseline['u:' + s.id] = { ingress: s.rawIngress || 0, egress: s.rawEgress || 0 };""")
rep("""            rawSocketsData.forEach(r => {
                if (r.drops != null) baseline['i:' + r.inode] = r.rawDrops;
                if (r.drops != null) r.drops = 0;
                r.dropRate = 0;
            });
""", "")

a = s.index("        function applyData(d) {")
b = s.index("        let helperNote = '';")
s = s[:a] + """        function applyData(d) {
            if (d.os) document.getElementById('os-label').textContent = d.os;
            liveTotals = d.totals || liveTotals;
            liveMode = d.mode || 'etw';
            servicesData = (d.services || []).map(s => {
                const b = baseline['u:' + s.id] || { ingress: 0, egress: 0 };
                const inK = s.ingressRate == null ? null : s.ingressRate / 1024;
                const outK = s.egressRate == null ? null : s.egressRate / 1024;
                return {
                    id: s.id, name: s.name, monitored: s.monitored, active: s.activeState === 'active',
                    search: [s.name, s.displayName, s.process, String(s.pid)].concat(s.members || []).join(' ').toLowerCase(),
                    title: s.description || '', conns: s.connections,
                    rawIngress: s.ingress, rawEgress: s.egress,
                    ingress: s.ingress == null ? null : Math.max(0, s.ingress - b.ingress),
                    egress: s.egress == null ? null : Math.max(0, s.egress - b.egress),
                    inKBPS: inK, outKBPS: outK,
                    rateKBPS: (inK == null && outK == null) ? null : (inK || 0) + (outK || 0),
                    history: (s.history && s.history.length) ? s.history.slice(-10) : [0, 0, 0, 0, 0]
                };
            });
            const kindLabel = { driver: 'DRIVER', capture: 'CAPTURE', raw: 'RAW', wfp: 'WFP', callout: 'CALLOUT' };
            rawSocketsData = (d.sockets || []).map(x => ({
                kind: x.kind, kindLabel: kindLabel[x.kind] || String(x.kind || '?').toUpperCase(),
                procName: x.procName || 'unknown', pid: x.pid == null ? '-' : x.pid,
                proto: x.proto || 'n/a', detail: x.detail || 'n/a', count: x.count || 'n/a', title: x.title || ''
            }));
            rawNote = d.rawSocketsNote || '';
            const banner = document.getElementById('helper-banner');
            const msgs = d.banner || [];
            banner.textContent = msgs.join('  \\u2022  ');
            banner.title = msgs.join('\\n');
            banner.classList.toggle('hidden', msgs.length === 0);
            helperNote = msgs.join('; ');
        }
        let rawNote = '';
""" + s[b:]

rep("""                statusText.textContent = 'LIVE D-BUS POLLING';
                statusText.title = helperNote;""",
    """                const full = liveMode === 'etw';
                statusDot.className = 'inline-block w-2 h-2 rounded-full ' + (full ? 'bg-emerald-500' : 'bg-amber-500') + ' animate-subtle';
                statusText.className = (full ? 'text-emerald-400' : 'text-amber-400') + ' font-medium';
                statusText.textContent = full ? 'LIVE ETW POLLING' : (liveMode === 'fallback' ? 'LIVE \\u00b7 FALLBACK (NO ETW)' : 'LIVE \\u00b7 NO ETW BYTES');
                statusText.title = helperNote;""")
rep("        // Render Top Section: Systemd Network Services (Sorted Top-Down by usage)",
    "        // Render Top Section: Windows Services (Sorted Top-Down by usage)")
rep("const filtered = servicesData.filter(s => s.name.toLowerCase().includes(searchQuery));",
    "const filtered = servicesData.filter(s => s.search.includes(searchQuery));")
rep("""                const totalBytesFormatted = service.monitored ? formatBytes(service.ingress + service.egress) : 'n/a';""",
    """                const totalBytesFormatted = service.monitored ? formatBytes(service.ingress + service.egress)
                    : (service.conns ? `${Number(service.conns.tcp) + Number(service.conns.udp)} conns` : 'n/a');""")
rep("""title="${service.monitored ? '' : 'IPAccounting is off for this unit'}">${esc(service.name)}</span>""",
    """title="${esc(service.title)}${service.monitored ? '' : ' (no ETW byte counters)'}">${esc(service.name)}</span>""")
rep("""                html = `<div class="p-4 text-center text-slate-500">${helperNote && !servicesData.length ? esc(helperNote) : 'No matching systemd units found.'}</div>`;""",
    """                html = `<div class="p-4 text-center text-slate-500">${helperNote && !servicesData.length ? esc(helperNote) : 'No matching Windows services found.'}</div>`;""")
rep("        // Render Bottom Section: Raw Sockets Panel", "        // Render Bottom Section: Capture / Raw / WFP Panel")
rep("""            rawSocketsData.forEach((sock, index) => {""",
    """            const rows = rawSocketsData.filter(r => showWfp || (r.kind !== 'wfp' && r.kind !== 'callout'));
            rows.forEach((sock, index) => {""")
rep("""                        <!-- Inode -->
                        <div class="col-span-2 sm:col-span-1 text-slate-500 font-mono text-[11px]">
                            #${esc(sock.inode)}
                        </div>""",
    """                        <!-- Kind -->
                        <div class="col-span-2 sm:col-span-1 text-slate-500 font-mono text-[11px]">
                            ${esc(sock.kindLabel)}
                        </div>""")
rep("""                            <span class="truncate">${esc(sock.procName)}</span>""",
    """                            <span class="truncate" title="${esc(sock.title)}">${esc(sock.procName)}</span>""")
rep("""                            <span class="bg-slate-800 text-slate-300 px-1.5 py-0.5 rounded border border-slate-700">${esc(sock.proto)}</span>""",
    """                            <span class="bg-slate-800 text-slate-300 px-1.5 py-0.5 rounded border border-slate-700 truncate inline-block max-w-full align-middle" title="${esc(sock.proto)}">${esc(sock.proto)}</span>""")
rep("""                        <!-- Packet Rate -->
                        <div class="col-span-3 sm:col-span-2 text-right text-amber-400 font-semibold">
                            ${sock.dropRate == null ? 'n/a' : sock.dropRate.toFixed(1) + ' drops/s'}
                        </div>

                        <!-- Total Packets -->
                        <div class="hidden sm:block sm:col-span-3 text-right text-slate-400 text-[11px]">
                            ${sock.drops != null ? sock.drops.toLocaleString() + ' drops' : (sock.rmem != null ? formatBytes(sock.rmem) + ' rmem' : 'n/a')}
                        </div>""",
    """                        <!-- Detail -->
                        <div class="col-span-3 sm:col-span-2 text-right text-amber-400 font-semibold truncate">
                            ${esc(sock.detail)}
                        </div>

                        <!-- Count -->
                        <div class="hidden sm:block sm:col-span-3 text-right text-slate-400 text-[11px]">
                            ${esc(sock.count)}
                        </div>""")
rep("""            if (!rawSocketsData.length) html = `<div class="p-4 text-center text-slate-500">No raw or packet sockets open.</div>`;""",
    """            if (!rows.length) html = `<div class="p-4 text-center text-slate-500">${rawSocketsData.length ? 'WFP rows hidden [ W ].' : 'No capture-driver users found' + (liveTotals.wfpFilters == null ? ' (netmon-raw unavailable or not elevated).' : '.')}</div>`;
            if (rawNote) html += `<div class="px-3 py-1.5 text-[10px] text-slate-600">${esc(rawNote)}</div>`;""")
rep("""            document.getElementById('active-units-count').textContent = `${liveTotals.monitored} / ${liveTotals.running} active`;
            document.getElementById('raw-sockets-count').textContent = `${rawSocketsData.length} sockets tracked`;""",
    """            document.getElementById('active-units-count').textContent = `${liveTotals.monitored} / ${liveTotals.running} running`;
            const na = v => v == null ? 'n/a' : v;
            document.getElementById('raw-sockets-count').textContent =
                `${na(liveTotals.capture)} capture \\u00b7 ${na(liveTotals.raw)} raw \\u00b7 ${na(liveTotals.wfpFilters)} WFP`;""")
rep("""        // Drawer Controls""", """        // WFP rows toggle (W)
        function toggleWfp() {
            showWfp = !showWfp;
            document.getElementById('btn-wfp').textContent = showWfp ? 'WFP: ON' : 'WFP: OFF';
            renderRawSockets();
        }

        // Drawer Controls""")
for bad in ("D-Bus", "systemd", "IPAccounting", "/proc/net", "lastDrops", "dropRate", "inode"):
    if bad in s:
        idx = s.index(bad)
        raise SystemExit("leftover %r near: %r" % (bad, s[idx-80:idx+40]))
open(sys.argv[2], "w", encoding="utf-8").write(s)
print("ok", len(src.splitlines()), "->", len(s.splitlines()), "lines")
