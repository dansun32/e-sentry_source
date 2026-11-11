#pragma once
#include "core.hpp"

namespace netmon {
// Each writes one JSON value into w (the caller writes the key).
void write_capture_drivers(JsonWriter& w);                          // Npcap / WinPcap install state
void write_module_scan(JsonWriter& w, const std::vector<std::string>& extra_out_errors);
void write_handle_scan(JsonWriter& w, unsigned timeout_ms, bool enabled, std::vector<std::pair<unsigned long, std::string>>& raw_owners);
void write_adapters(JsonWriter& w);
bool enable_debug_privilege();
}  // namespace netmon
