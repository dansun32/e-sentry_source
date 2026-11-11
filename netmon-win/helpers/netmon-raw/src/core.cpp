#include "core.hpp"

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <set>
#include <tuple>

namespace netmon {

const char* const kVersion = "1.0.0";
const char* const kUsage =
    "netmon-raw - read-only snapshot of packet-capture users and WFP filters (JSON on stdout)\n"
    "\n"
    "usage: netmon-raw.exe [--no-wfp] [--no-modules] [--no-adapters] [--handles]\n"
    "                      [--handle-timeout-ms N] [--max-callouts N]\n"
    "\n"
    "  --no-wfp            skip the WFP filter/callout summary\n"
    "  --no-modules        skip the per-process wpcap.dll/Packet.dll module scan\n"
    "  --no-adapters       skip listing Npcap adapters (loads wpcap.dll in this process)\n"
    "  --handles           OPTIONAL handle scan (NtQuerySystemInformation) for processes holding\n"
    "                      \\Device\\NPCAP* / \\Device\\NPF_* / \\Device\\RawIp*; undocumented API,\n"
    "                      guarded by a per-handle timeout thread; may be flagged by antivirus\n"
    "  --handle-timeout-ms N   per-handle name query timeout (20..2000, default 150)\n"
    "\n"
    "Most data needs Administrator; without it the JSON says what was skipped.\n";

std::string lower(std::string s) {
    for (auto& c : s) if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    return s;
}

std::string json_escape(const std::string& s) {
    std::string o;
    o.reserve(s.size() + 8);
    for (unsigned char c : s) {
        switch (c) {
            case '"': o += "\\\""; break;
            case '\\': o += "\\\\"; break;
            case '\n': o += "\\n"; break;
            case '\r': o += "\\r"; break;
            case '\t': o += "\\t"; break;
            case '<': o += "\\u003c"; break;
            case '>': o += "\\u003e"; break;
            case '&': o += "\\u0026"; break;
            default:
                if (c < 0x20 || c == 0x7f) {
                    char b[8];
                    std::snprintf(b, sizeof b, "\\u%04x", c);
                    o += b;
                } else {
                    o += static_cast<char>(c);
                }
        }
    }
    return o;
}

void JsonWriter::comma() {
    if (after_key_) { after_key_ = false; return; }
    if (!first_.empty()) {
        if (!first_.back()) out_ += ',';
        first_.back() = false;
    }
}
JsonWriter& JsonWriter::begin_object() { comma(); out_ += '{'; first_.push_back(true); return *this; }
JsonWriter& JsonWriter::end_object() { out_ += '}'; first_.pop_back(); return *this; }
JsonWriter& JsonWriter::begin_array() { comma(); out_ += '['; first_.push_back(true); return *this; }
JsonWriter& JsonWriter::end_array() { out_ += ']'; first_.pop_back(); return *this; }
JsonWriter& JsonWriter::key(const std::string& k) {
    comma();
    out_ += '"'; out_ += json_escape(k); out_ += "\":";
    after_key_ = true;
    return *this;
}
JsonWriter& JsonWriter::value(const std::string& s) { comma(); out_ += '"'; out_ += json_escape(s); out_ += '"'; return *this; }
JsonWriter& JsonWriter::value(const char* s) { return s ? value(std::string(s)) : null(); }
JsonWriter& JsonWriter::value(bool b) { comma(); out_ += b ? "true" : "false"; return *this; }
JsonWriter& JsonWriter::value(int64_t n) { comma(); out_ += std::to_string(n); return *this; }
JsonWriter& JsonWriter::value(uint64_t n) { comma(); out_ += std::to_string(n); return *this; }
JsonWriter& JsonWriter::value(double d) {
    if (!std::isfinite(d)) return null();
    comma();
    char b[64];
    std::snprintf(b, sizeof b, "%.3f", d);
    out_ += b;
    return *this;
}
JsonWriter& JsonWriter::null() { comma(); out_ += "null"; return *this; }

std::string wfp_action_name(uint32_t t) {
    // FWP_ACTION_FLAG_TERMINATING 0x1000, NON_TERMINATING 0x2000, CALLOUT 0x4000
    switch (t) {
        case 0x1001: return "block";
        case 0x1002: return "permit";
        case 0x5003: return "callout_terminating";
        case 0x6004: return "callout_inspection";
        case 0x4005: return "callout_unknown";
        default: return "other";
    }
}

std::vector<WfpGroup> summarise_wfp(const std::vector<WfpFilter>& filters, size_t max_samples) {
    std::map<std::tuple<std::string, std::string, std::string>, WfpGroup> m;
    std::map<std::tuple<std::string, std::string, std::string>, std::set<std::string>> seen;
    for (const auto& f : filters) {
        auto prov = f.provider.empty() ? std::string("(no provider)") : f.provider;
        auto k = std::make_tuple(prov, f.layer, f.action);
        auto& g = m[k];
        if (g.count == 0) { g.provider = prov; g.layer = f.layer; g.action = f.action; }
        ++g.count;
        auto& s = seen[k];
        if (!f.name.empty() && g.sample_names.size() < max_samples && s.insert(f.name).second)
            g.sample_names.push_back(f.name);
    }
    std::vector<WfpGroup> out;
    out.reserve(m.size());
    for (auto& kv : m) out.push_back(std::move(kv.second));
    std::stable_sort(out.begin(), out.end(), [](const WfpGroup& a, const WfpGroup& b) {
        if (a.count != b.count) return a.count > b.count;
        return std::tie(a.provider, a.layer, a.action) < std::tie(b.provider, b.layer, b.action);
    });
    return out;
}

static bool starts_with(const std::string& s, const std::string& p) { return s.compare(0, p.size(), p) == 0; }

DeviceKind classify_device(const std::string& name) {
    const auto n = lower(name);
    if (n == "\\device\\npcap" || starts_with(n, "\\device\\npcap_") || starts_with(n, "\\device\\npf_") ||
        n == "\\device\\npf")
        return DeviceKind::Capture;
    if (n == "\\device\\rawip" || n == "\\device\\rawip6" || starts_with(n, "\\device\\rawip\\") ||
        starts_with(n, "\\device\\rawip6\\"))
        return DeviceKind::RawLegacy;
    return DeviceKind::None;
}

bool is_capture_module(const std::string& base) {
    const auto n = lower(base);
    return n == "wpcap.dll" || n == "packet.dll";
}

Options parse_args(const std::vector<std::string>& args) {
    Options o;
    for (size_t i = 0; i < args.size(); ++i) {
        const auto& a = args[i];
        auto num = [&](unsigned lo, unsigned hi, unsigned& dst) {
            if (i + 1 >= args.size()) { o.error = a + " needs a value"; return; }
            const auto& v = args[++i];
            if (v.empty() || v.size() > 6 || v.find_first_not_of("0123456789") != std::string::npos) {
                o.error = a + ": not a number"; return;
            }
            unsigned long n = std::stoul(v);
            if (n < lo || n > hi) { o.error = a + " out of range"; return; }
            dst = static_cast<unsigned>(n);
        };
        if (a == "--no-wfp") o.wfp = false;
        else if (a == "--no-modules") o.modules = false;
        else if (a == "--no-adapters") o.adapters = false;
        else if (a == "--handles") o.handles = true;
        else if (a == "--handle-timeout-ms") num(20, 2000, o.handle_timeout_ms);
        else if (a == "--max-callouts") num(0, 100000, o.max_callouts);
        else if (a == "-h" || a == "--help" || a == "/?") o.help = true;
        else if (a == "--version") o.version = true;
        else o.error = "unknown argument: " + a;
        if (!o.error.empty()) break;
    }
    return o;
}

}  // namespace netmon
