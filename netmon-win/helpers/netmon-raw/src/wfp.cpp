// Read-only summary of Windows Filtering Platform filters and callouts (Fwpm* user-mode API).
// This is where VPN killswitches (e.g. PIA), firewalls and packet-inspection drivers register
// their rules; it is the closest Windows analogue of "what can bypass / see below the stack".
#include "wfp.hpp"
#include "win_util.hpp"

#include <fwpmu.h>

#include <map>

namespace netmon {

namespace {
struct GuidLess {
    bool operator()(const GUID& a, const GUID& b) const { return memcmp(&a, &b, sizeof(GUID)) < 0; }
};
}  // namespace

void write_wfp(JsonWriter& w, unsigned max_callouts) {
    w.begin_object();
    HANDLE engine = nullptr;
    DWORD rc = FwpmEngineOpen0(nullptr, RPC_C_AUTHN_DEFAULT, nullptr, nullptr, &engine);
    if (rc != ERROR_SUCCESS) {
        w.kv("available", false)
            .kv("error", "FwpmEngineOpen0: " + win_err(rc) + (rc == ERROR_ACCESS_DENIED ? " (run as Administrator)" : ""))
            .end_object();
        return;
    }

    std::map<GUID, std::string, GuidLess> providers;
    {
        HANDLE e = nullptr;
        if (FwpmProviderCreateEnumHandle0(engine, nullptr, &e) == ERROR_SUCCESS) {
            for (;;) {
                FWPM_PROVIDER0** arr = nullptr;
                UINT32 n = 0;
                if (FwpmProviderEnum0(engine, e, 256, &arr, &n) != ERROR_SUCCESS || n == 0) { if (arr) FwpmFreeMemory0(reinterpret_cast<void**>(&arr)); break; }
                for (UINT32 i = 0; i < n; ++i)
                    providers[arr[i]->providerKey] = arr[i]->displayData.name ? utf8(arr[i]->displayData.name) : guid_str(arr[i]->providerKey);
                FwpmFreeMemory0(reinterpret_cast<void**>(&arr));
                if (n < 256) break;
            }
            FwpmProviderDestroyEnumHandle0(engine, e);
        }
    }
    std::map<GUID, std::string, GuidLess> layers;
    auto layer_name = [&](const GUID& k) -> std::string {
        auto it = layers.find(k);
        if (it != layers.end()) return it->second;
        FWPM_LAYER0* l = nullptr;
        std::string n = guid_str(k);
        if (FwpmLayerGetByKey0(engine, &k, &l) == ERROR_SUCCESS && l) {
            if (l->displayData.name) n = utf8(l->displayData.name);
            FwpmFreeMemory0(reinterpret_cast<void**>(&l));
        }
        return layers[k] = n;
    };
    auto provider_name = [&](const GUID* k) -> std::string {
        if (!k) return "";
        auto it = providers.find(*k);
        return it != providers.end() ? it->second : guid_str(*k);
    };

    std::vector<WfpFilter> filters;
    std::string filter_err;
    {
        HANDLE e = nullptr;
        DWORD r = FwpmFilterCreateEnumHandle0(engine, nullptr, &e);
        if (r != ERROR_SUCCESS) filter_err = "FwpmFilterCreateEnumHandle0: " + win_err(r);
        else {
            for (;;) {
                FWPM_FILTER0** arr = nullptr;
                UINT32 n = 0;
                r = FwpmFilterEnum0(engine, e, 512, &arr, &n);
                if (r != ERROR_SUCCESS) { filter_err = "FwpmFilterEnum0: " + win_err(r); break; }
                for (UINT32 i = 0; i < n; ++i) {
                    const auto* f = arr[i];
                    filters.push_back({provider_name(f->providerKey), layer_name(f->layerKey),
                                       wfp_action_name(f->action.type),
                                       f->displayData.name ? utf8(f->displayData.name) : std::string()});
                }
                if (arr) FwpmFreeMemory0(reinterpret_cast<void**>(&arr));
                if (n < 512) break;
            }
            FwpmFilterDestroyEnumHandle0(engine, e);
        }
    }

    struct Callout { std::string provider, name, layer; };
    std::vector<Callout> callouts;
    uint64_t callout_total = 0;
    std::string callout_err;
    {
        HANDLE e = nullptr;
        DWORD r = FwpmCalloutCreateEnumHandle0(engine, nullptr, &e);
        if (r != ERROR_SUCCESS) callout_err = "FwpmCalloutCreateEnumHandle0: " + win_err(r);
        else {
            for (;;) {
                FWPM_CALLOUT0** arr = nullptr;
                UINT32 n = 0;
                r = FwpmCalloutEnum0(engine, e, 256, &arr, &n);
                if (r != ERROR_SUCCESS) { callout_err = "FwpmCalloutEnum0: " + win_err(r); break; }
                for (UINT32 i = 0; i < n; ++i) {
                    ++callout_total;
                    if (callouts.size() < max_callouts)
                        callouts.push_back({provider_name(arr[i]->providerKey),
                                            arr[i]->displayData.name ? utf8(arr[i]->displayData.name) : guid_str(arr[i]->calloutKey),
                                            layer_name(arr[i]->applicableLayer)});
                }
                if (arr) FwpmFreeMemory0(reinterpret_cast<void**>(&arr));
                if (n < 256) break;
            }
            FwpmCalloutDestroyEnumHandle0(engine, e);
        }
    }
    FwpmEngineClose0(engine);

    w.kv("available", true);
    std::string err = filter_err.empty() ? callout_err : (callout_err.empty() ? filter_err : filter_err + "; " + callout_err);
    if (err.empty()) w.kv_null("error"); else w.kv("error", err + (err.find("error 5:") != std::string::npos ? " (run as Administrator)" : ""));
    w.kv("filterCount", static_cast<uint64_t>(filters.size())).kv("calloutCount", callout_total);
    w.key("providers").begin_array();
    for (auto& p : providers) w.begin_object().kv("key", guid_str(p.first)).kv("name", p.second).end_object();
    w.end_array();
    w.key("summary").begin_array();
    auto groups = summarise_wfp(filters);
    size_t shown = 0;
    for (auto& g : groups) {
        if (++shown > 300) break;
        w.begin_object().kv("provider", g.provider).kv("layer", g.layer).kv("action", g.action).kv("count", g.count);
        w.key("sampleNames").begin_array();
        for (auto& n : g.sample_names) w.value(n);
        w.end_array().end_object();
    }
    w.end_array();
    w.kv("summaryTruncated", groups.size() > 300);
    w.key("callouts").begin_array();
    for (auto& c : callouts) w.begin_object().kv("provider", c.provider.empty() ? "(no provider)" : c.provider).kv("name", c.name).kv("layer", c.layer).end_object();
    w.end_array();
    w.end_object();
}

}  // namespace netmon
