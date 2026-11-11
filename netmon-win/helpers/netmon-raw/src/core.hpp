// Portable (OS-independent) pieces of netmon-raw: JSON writing, WFP summarising,
// device/module classification and argument parsing. Unit-tested on any OS.
#pragma once
#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace netmon {

// ---------------------------------------------------------------- JSON
std::string json_escape(const std::string& utf8);  // escapes ", \, control chars, <, >, &

class JsonWriter {
public:
    JsonWriter& begin_object();
    JsonWriter& end_object();
    JsonWriter& begin_array();
    JsonWriter& end_array();
    JsonWriter& key(const std::string& k);
    JsonWriter& value(const std::string& s);
    JsonWriter& value(const char* s);
    JsonWriter& value(bool b);
    JsonWriter& value(int64_t n);
    JsonWriter& value(uint64_t n);
    JsonWriter& value(int n) { return value(static_cast<int64_t>(n)); }
    JsonWriter& value(unsigned n) { return value(static_cast<uint64_t>(n)); }
    JsonWriter& value(double d);
    JsonWriter& null();
    template <class T> JsonWriter& kv(const std::string& k, const T& v) { key(k); return value(v); }
    JsonWriter& kv_null(const std::string& k) { key(k); return null(); }
    const std::string& str() const { return out_; }

private:
    void comma();
    std::string out_;
    std::vector<bool> first_;  // per nesting level: no element written yet
    bool after_key_ = false;
};

// ---------------------------------------------------------------- WFP summary
struct WfpFilter {
    std::string provider;  // provider display name, or "" when the filter has no provider
    std::string layer;     // layer display name (or GUID string)
    std::string action;    // block / permit / callout_terminating / callout_inspection / callout_unknown / other
    std::string name;      // filter display name
};

struct WfpGroup {
    std::string provider, layer, action;
    uint64_t count = 0;
    std::vector<std::string> sample_names;  // first few distinct names
};

// Group filters by (provider, layer, action); sorted by count desc, then provider/layer/action.
std::vector<WfpGroup> summarise_wfp(const std::vector<WfpFilter>& filters, size_t max_samples = 3);
std::string wfp_action_name(uint32_t fwp_action_type);  // FWP_ACTION_* numeric value -> name

// ---------------------------------------------------------------- classification
enum class DeviceKind { None, Capture, RawLegacy };
// \Device\NPCAP, \Device\NPCAP_{GUID}, \Device\NPCAP_LOOPBACK, \Device\NPF_{GUID} -> Capture
// \Device\RawIp, \Device\RawIp6 (legacy TDI raw transport) -> RawLegacy
DeviceKind classify_device(const std::string& object_name);
// wpcap.dll / packet.dll (any case) -> true
bool is_capture_module(const std::string& base_name);
std::string lower(std::string s);

// ---------------------------------------------------------------- args
struct Options {
    bool wfp = true, modules = true, adapters = true, handles = false;
    unsigned handle_timeout_ms = 150;
    unsigned max_callouts = 200;
    bool help = false, version = false;
    std::string error;  // non-empty: bad arguments
};
Options parse_args(const std::vector<std::string>& args);
extern const char* const kUsage;
extern const char* const kVersion;

}  // namespace netmon
