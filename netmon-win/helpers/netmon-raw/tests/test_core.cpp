// Minimal self-contained test runner (no framework download needed); registered with CTest.
#include "../src/core.hpp"

#include <cstdio>
#include <string>

static int failures = 0, checks = 0;
#define CHECK(cond) do { ++checks; if (!(cond)) { ++failures; std::printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); } } while (0)

using namespace netmon;

int main() {
    // JSON escaping & structure
    CHECK(json_escape("a\"b\\c\n<x>&\x01") == "a\\\"b\\\\c\\n\\u003cx\\u003e\\u0026\\u0001");
    CHECK(json_escape("C:\\Windows\\System32\\Npcap\\wpcap.dll") == "C:\\\\Windows\\\\System32\\\\Npcap\\\\wpcap.dll");
    CHECK(json_escape("caf\xc3\xa9") == "caf\xc3\xa9");  // UTF-8 passes through
    JsonWriter w;
    w.begin_object().kv("a", 1).kv("b", std::string("x")).key("c").begin_array().value(true).null().value(2.5)
        .begin_object().kv("d", false).end_object().end_array().kv_null("e").key("f").begin_array().end_array().end_object();
    CHECK(w.str() == "{\"a\":1,\"b\":\"x\",\"c\":[true,null,2.500,{\"d\":false}],\"e\":null,\"f\":[]}");

    // WFP summary
    std::vector<WfpFilter> f = {
        {"Private Internet Access", "ALE Connect v4", "block", "PIA killswitch block all"},
        {"Private Internet Access", "ALE Connect v4", "block", "PIA killswitch block all"},
        {"Private Internet Access", "ALE Connect v4", "block", "PIA block IPv6"},
        {"Private Internet Access", "ALE Connect v4", "permit", "PIA allow tunnel"},
        {"", "Inbound Transport v4", "callout_inspection", ""},
        {"Microsoft Corporation", "ALE Connect v4", "block", "Boot-time filter"},
    };
    auto s = summarise_wfp(f, 3);
    CHECK(s.size() == 4);
    CHECK(s[0].provider == "Private Internet Access" && s[0].action == "block" && s[0].count == 3);
    CHECK(s[0].sample_names.size() == 2);  // distinct names only
    bool has_noprov = false;
    for (auto& g : s) if (g.provider == "(no provider)" && g.sample_names.empty()) has_noprov = true;
    CHECK(has_noprov);
    CHECK(wfp_action_name(0x1001) == "block");
    CHECK(wfp_action_name(0x1002) == "permit");
    CHECK(wfp_action_name(0x5003) == "callout_terminating");
    CHECK(wfp_action_name(0x6004) == "callout_inspection");
    CHECK(wfp_action_name(7) == "other");

    // device / module classification
    CHECK(classify_device("\\Device\\NPCAP") == DeviceKind::Capture);
    CHECK(classify_device("\\Device\\NPCAP_{D5D1C1F3-0000-4B1A-9C2B-000000000000}") == DeviceKind::Capture);
    CHECK(classify_device("\\Device\\NPCAP_LOOPBACK") == DeviceKind::Capture);
    CHECK(classify_device("\\Device\\NPF_{ABC}") == DeviceKind::Capture);
    CHECK(classify_device("\\Device\\RawIp6") == DeviceKind::RawLegacy);
    CHECK(classify_device("\\Device\\Afd\\Endpoint") == DeviceKind::None);
    CHECK(classify_device("\\Device\\NPCAPX") == DeviceKind::None);
    CHECK(is_capture_module("WPCAP.DLL") && is_capture_module("Packet.dll") && !is_capture_module("ws2_32.dll"));

    // args
    auto o = parse_args({"--handles", "--handle-timeout-ms", "300", "--no-wfp"});
    CHECK(o.error.empty() && o.handles && !o.wfp && o.handle_timeout_ms == 300 && o.modules);
    CHECK(!parse_args({"--handle-timeout-ms", "5"}).error.empty());
    CHECK(!parse_args({"--handle-timeout-ms", "-1"}).error.empty());
    CHECK(!parse_args({"--handle-timeout-ms"}).error.empty());
    CHECK(!parse_args({"--bogus"}).error.empty());
    CHECK(parse_args({}).handles == false);

    std::printf("%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
