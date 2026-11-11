// netmon-raw: read-only JSON snapshot of packet-capture users, raw-socket hints and WFP filters.
#include "capture.hpp"
#include "core.hpp"
#include "wfp.hpp"
#include "win_util.hpp"

#include <shellapi.h>

#include <cstdio>
#include <ctime>
#include <string>
#include <vector>

using namespace netmon;

static bool is_admin() {
    BOOL member = FALSE;
    SID_IDENTIFIER_AUTHORITY nt = SECURITY_NT_AUTHORITY;
    PSID admins = nullptr;
    if (AllocateAndInitializeSid(&nt, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &admins)) {
        if (!CheckTokenMembership(nullptr, admins, &member)) member = FALSE;
        FreeSid(admins);
    }
    return member != FALSE;  // true only when elevated (filtered admin tokens report false)
}

int main() {
    int argc = 0;
    LPWSTR* wargv = CommandLineToArgvW(GetCommandLineW(), &argc);
    std::vector<std::string> args;
    for (int i = 1; i < argc; ++i) args.push_back(utf8(wargv[i]));
    LocalFree(wargv);

    Options o = parse_args(args);
    if (!o.error.empty()) { std::fprintf(stderr, "%s\n\n%s", o.error.c_str(), kUsage); return 2; }
    if (o.help) { std::fputs(kUsage, stdout); return 0; }
    if (o.version) { std::printf("netmon-raw %s\n", kVersion); return 0; }

    const bool admin = is_admin();
    if (admin) enable_debug_privilege();  // lets us read modules of other users' processes; read-only use

    JsonWriter w;
    w.begin_object().kv("schema", "netmon-raw/1").kv("version", kVersion).kv("ts", static_cast<double>(std::time(nullptr)))
        .kv("admin", admin);
    w.key("capture").begin_object();
    w.key("drivers");
    write_capture_drivers(w);
    w.key("moduleScan");
    if (o.modules) write_module_scan(w, {});
    else w.begin_object().kv("disabled", true).end_object();
    std::vector<std::pair<unsigned long, std::string>> raw_owners;
    w.key("handleScan");
    write_handle_scan(w, o.handle_timeout_ms, o.handles, raw_owners);
    w.key("adapters");
    if (o.adapters) write_adapters(w);  // last: loading wpcap.dll must not influence the scans above
    else w.begin_object().kv("disabled", true).end_object();
    w.end_object();

    w.key("rawSockets").begin_object()
        .kv("supported", false)
        .kv("note", "Windows has no public API that lists SOCK_RAW owners (GetExtendedTcpTable/UdpTable cover TCP/UDP only). "
                    "Shown: legacy \\Device\\RawIp* handle holders when --handles is used; modern raw sockets are AFD "
                    "endpoints and cannot be told apart from other sockets without undocumented IOCTLs.")
        .key("legacyHandleOwners").begin_array();
    for (auto& r : raw_owners)
        w.begin_object().kv("pid", static_cast<uint64_t>(r.first)).kv("process", process_image(r.first)).kv("device", r.second).end_object();
    w.end_array().end_object();

    w.key("wfp");
    if (o.wfp) write_wfp(w, o.max_callouts);
    else w.begin_object().kv("available", false).kv("error", "disabled with --no-wfp").end_object();
    w.end_object();

    std::string out = w.str();
    out += '\n';
    std::fwrite(out.data(), 1, out.size(), stdout);
    std::fflush(stdout);
    return 0;
}
