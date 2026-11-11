// Packet-capture visibility: who can see packets below the normal socket layer.
//  1) Npcap / WinPcap install state from the SCM and System32 files.
//  2) PRIMARY, safe: processes that loaded wpcap.dll / Packet.dll (EnumProcessModulesEx).
//  3) OPTIONAL (--handles): processes holding \Device\NPCAP* / \Device\NPF_* (and legacy \Device\RawIp*)
//     handles, via the undocumented NtQuerySystemInformation(SystemExtendedHandleInformation) +
//     NtQueryObject(ObjectNameInformation). NtQueryObject can block forever on some synchronous
//     pipe handles, so pipes are skipped and every name query runs on a worker thread with a timeout.
// Everything here only reads; no handle is closed in, or injected into, any other process.
#include "capture.hpp"
#include "win_util.hpp"

#include <psapi.h>

#include <algorithm>
#include <cstdio>
#include <chrono>
#include <map>
#include <set>
#include <vector>

namespace netmon {

// ------------------------------------------------------------------ driver install state
static void write_service_state(JsonWriter& w, const wchar_t* name) {
    w.begin_object().kv("service", utf8(name));
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    std::string state = "unknown";
    if (scm) {
        SC_HANDLE s = OpenServiceW(scm, name, SERVICE_QUERY_STATUS);
        if (!s) {
            state = GetLastError() == ERROR_SERVICE_DOES_NOT_EXIST ? "missing" : "unknown";
        } else {
            SERVICE_STATUS st{};
            if (QueryServiceStatus(s, &st)) state = st.dwCurrentState == SERVICE_RUNNING ? "running"
                                                    : st.dwCurrentState == SERVICE_STOPPED ? "stopped" : "other";
            CloseServiceHandle(s);
        }
        CloseServiceHandle(scm);
    }
    w.kv("state", state);
}

static std::wstring system_dir() {
    wchar_t b[MAX_PATH];
    UINT n = GetSystemDirectoryW(b, MAX_PATH);
    return std::wstring(b, n);
}

static bool file_exists(const std::wstring& p) {
    DWORD a = GetFileAttributesW(p.c_str());
    return a != INVALID_FILE_ATTRIBUTES && !(a & FILE_ATTRIBUTE_DIRECTORY);
}

void write_capture_drivers(JsonWriter& w) {
    const auto sys = system_dir();
    w.begin_object();
    w.key("npcap");
    write_service_state(w, L"npcap");
    auto np = sys + L"\\Npcap\\wpcap.dll";
    w.key("dll");
    if (file_exists(np)) w.value(utf8(np)); else w.null();
    w.end_object();
    w.key("winpcap");
    write_service_state(w, L"npf");
    auto wp = sys + L"\\wpcap.dll";
    w.key("dll");
    if (file_exists(wp)) w.value(utf8(wp)); else w.null();
    w.end_object();
    w.end_object();
}

// ------------------------------------------------------------------ module scan (primary)
void write_module_scan(JsonWriter& w, const std::vector<std::string>&) {
    std::vector<DWORD> pids(4096);
    DWORD bytes = 0;
    for (;;) {
        if (!EnumProcesses(pids.data(), static_cast<DWORD>(pids.size() * sizeof(DWORD)), &bytes)) {
            w.begin_object().kv("error", "EnumProcesses: " + win_err(GetLastError())).end_object();
            return;
        }
        if (bytes < pids.size() * sizeof(DWORD)) break;
        pids.resize(pids.size() * 2);
    }
    pids.resize(bytes / sizeof(DWORD));
    const DWORD self = GetCurrentProcessId();
    unsigned scanned = 0, inaccessible = 0;
    w.begin_object().key("processes").begin_array();
    for (DWORD pid : pids) {
        if (pid == 0 || pid == 4 || pid == self) continue;
        HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        if (!h) { ++inaccessible; continue; }
        std::vector<HMODULE> mods(512);
        DWORD need = 0;
        bool ok = false;
        for (int tries = 0; tries < 3; ++tries) {
            if (!EnumProcessModulesEx(h, mods.data(), static_cast<DWORD>(mods.size() * sizeof(HMODULE)), &need, LIST_MODULES_ALL)) break;
            if (need <= mods.size() * sizeof(HMODULE)) { ok = true; mods.resize(need / sizeof(HMODULE)); break; }
            mods.resize(need / sizeof(HMODULE) + 64);
        }
        if (!ok) { ++inaccessible; CloseHandle(h); continue; }
        ++scanned;
        std::vector<std::pair<std::string, std::string>> hits;  // base, full path
        for (HMODULE m : mods) {
            wchar_t base[MAX_PATH];
            DWORD n = GetModuleBaseNameW(h, m, base, MAX_PATH);
            if (!n) continue;
            auto b = utf8(base, static_cast<int>(n));
            if (!is_capture_module(b)) continue;
            wchar_t full[MAX_PATH * 2];
            DWORD fn = GetModuleFileNameExW(h, m, full, MAX_PATH * 2);
            hits.emplace_back(b, fn ? utf8(full, static_cast<int>(fn)) : std::string());
        }
        CloseHandle(h);
        if (hits.empty()) continue;
        std::string path;
        auto name = process_image(pid, &path);
        w.begin_object().kv("pid", static_cast<uint64_t>(pid)).kv("process", name).kv("path", path);
        w.key("modules").begin_array();
        for (auto& hm : hits) w.begin_object().kv("name", hm.first).kv("path", hm.second).end_object();
        w.end_array().end_object();
    }
    w.end_array().kv("scanned", static_cast<uint64_t>(scanned)).kv("inaccessible", static_cast<uint64_t>(inaccessible)).end_object();
}

// ------------------------------------------------------------------ handle scan (optional)
namespace {
constexpr LONG kStatusInfoLengthMismatch = static_cast<LONG>(0xC0000004L);
constexpr ULONG kSystemExtendedHandleInformation = 64;
constexpr ULONG kObjectNameInformation = 1;

struct HandleEntryEx {
    PVOID Object;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR HandleValue;
    ULONG GrantedAccess;
    USHORT CreatorBackTraceIndex;
    USHORT ObjectTypeIndex;
    ULONG HandleAttributes;
    ULONG Reserved;
};
struct HandleInfoEx {
    ULONG_PTR NumberOfHandles;
    ULONG_PTR Reserved;
    HandleEntryEx Handles[1];
};
struct UnicodeStr { USHORT Length; USHORT MaximumLength; PWSTR Buffer; };

using NtQuerySystemInformation_t = LONG(NTAPI*)(ULONG, PVOID, ULONG, PULONG);
using NtQueryObject_t = LONG(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);

struct NameJob {
    NtQueryObject_t query = nullptr;
    HANDLE handle = nullptr;
    std::wstring result;
    bool ok = false;
};

DWORD WINAPI name_worker(LPVOID p) {
    auto* job = static_cast<NameJob*>(p);
    alignas(8) static thread_local unsigned char buf[4096];
    ULONG ret = 0;
    if (job->query(job->handle, kObjectNameInformation, buf, sizeof buf, &ret) >= 0) {
        auto* us = reinterpret_cast<UnicodeStr*>(buf);
        if (us->Buffer && us->Length) job->result.assign(us->Buffer, us->Length / sizeof(wchar_t));
        job->ok = true;
    }
    return 0;
}
}  // namespace

bool enable_debug_privilege() {
    HANDLE tok = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tok)) return false;
    TOKEN_PRIVILEGES tp{};
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    bool ok = LookupPrivilegeValueW(nullptr, L"SeDebugPrivilege", &tp.Privileges[0].Luid) &&
              AdjustTokenPrivileges(tok, FALSE, &tp, sizeof tp, nullptr, nullptr) && GetLastError() == ERROR_SUCCESS;
    CloseHandle(tok);
    return ok;
}

void write_handle_scan(JsonWriter& w, unsigned timeout_ms, bool enabled,
                       std::vector<std::pair<unsigned long, std::string>>& raw_owners) {
    w.begin_object().kv("enabled", enabled);
    if (!enabled) { w.kv("note", "off by default; run with --handles to inspect \\Device\\NPCAP / NPF_ handles").end_object(); return; }
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    auto qsi = reinterpret_cast<NtQuerySystemInformation_t>(reinterpret_cast<void*>(GetProcAddress(ntdll, "NtQuerySystemInformation")));
    auto qo = reinterpret_cast<NtQueryObject_t>(reinterpret_cast<void*>(GetProcAddress(ntdll, "NtQueryObject")));
    if (!qsi || !qo) { w.kv("error", "ntdll exports not found").end_object(); return; }

    // Learn the "File" object type index from a handle we own.
    wchar_t self_path[MAX_PATH * 2];
    GetModuleFileNameW(nullptr, self_path, MAX_PATH * 2);
    HANDLE probe = CreateFileW(self_path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                               OPEN_EXISTING, 0, nullptr);

    std::vector<unsigned char> buf(1 << 20);
    LONG st = 0;
    for (int i = 0; i < 8; ++i) {
        ULONG need = 0;
        st = qsi(kSystemExtendedHandleInformation, buf.data(), static_cast<ULONG>(buf.size()), &need);
        if (st != kStatusInfoLengthMismatch) break;
        buf.resize(std::max<size_t>(buf.size() * 2, static_cast<size_t>(need) + (1 << 16)));
    }
    if (st < 0) {
        if (probe != INVALID_HANDLE_VALUE) CloseHandle(probe);
        char b[32];
        std::snprintf(b, sizeof b, "0x%08lx", static_cast<unsigned long>(st));
        w.kv("error", std::string("NtQuerySystemInformation failed: ") + b).end_object();
        return;
    }
    auto* info = reinterpret_cast<HandleInfoEx*>(buf.data());
    const DWORD self = GetCurrentProcessId();
    int file_type = -1;
    for (ULONG_PTR i = 0; i < info->NumberOfHandles; ++i) {
        const auto& e = info->Handles[i];
        if (e.UniqueProcessId == self && reinterpret_cast<HANDLE>(e.HandleValue) == probe) { file_type = e.ObjectTypeIndex; break; }
    }
    if (probe != INVALID_HANDLE_VALUE) CloseHandle(probe);
    if (file_type < 0) { w.kv("error", "could not determine File object type index").end_object(); return; }

    std::map<DWORD, HANDLE> procs;
    std::map<DWORD, std::set<std::string>> capture;
    unsigned checked = 0, timeouts = 0, denied = 0, skipped_pipes = 0;
    bool aborted = false;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(20);
    for (ULONG_PTR i = 0; i < info->NumberOfHandles; ++i) {
        const auto& e = info->Handles[i];
        const DWORD pid = static_cast<DWORD>(e.UniqueProcessId);
        if (e.ObjectTypeIndex != file_type || pid == self || pid == 4 || pid == 0) continue;
        if (timeouts >= 5 || std::chrono::steady_clock::now() > deadline) { aborted = true; break; }
        HANDLE ph;
        auto it = procs.find(pid);
        if (it == procs.end()) ph = procs[pid] = OpenProcess(PROCESS_DUP_HANDLE, FALSE, pid);
        else ph = it->second;
        if (!ph) { ++denied; continue; }
        HANDLE dup = nullptr;
        if (!DuplicateHandle(ph, reinterpret_cast<HANDLE>(e.HandleValue), GetCurrentProcess(), &dup, 0, FALSE, 0)) { ++denied; continue; }
        if (GetFileType(dup) == FILE_TYPE_PIPE) { ++skipped_pipes; CloseHandle(dup); continue; }  // classic hang source
        // Heap job: if the worker hangs we abandon it and must not free memory it still uses.
        auto* job = new NameJob;
        job->query = qo;
        job->handle = dup;
        HANDLE th = CreateThread(nullptr, 64 * 1024, name_worker, job, 0, nullptr);
        if (!th) { CloseHandle(dup); delete job; continue; }
        if (WaitForSingleObject(th, timeout_ms) == WAIT_TIMEOUT) {
            // Hung inside NtQueryObject on this handle: kill the worker so process exit cannot block,
            // leak the job/dup handle on purpose, and give up after a few of these.
            ++timeouts;
            TerminateThread(th, 1);
            CloseHandle(th);
            continue;
        }
        CloseHandle(th);
        CloseHandle(dup);
        ++checked;
        std::wstring result = job->ok ? job->result : std::wstring();
        delete job;
        if (result.empty()) continue;
        auto name = utf8(result);
        auto kind = classify_device(name);
        if (kind == DeviceKind::Capture) capture[pid].insert(name);
        else if (kind == DeviceKind::RawLegacy) raw_owners.emplace_back(pid, name);
    }
    for (auto& kv : procs) if (kv.second) CloseHandle(kv.second);

    w.key("processes").begin_array();
    for (auto& kv : capture) {
        w.begin_object().kv("pid", static_cast<uint64_t>(kv.first)).kv("process", process_image(kv.first));
        w.key("devices").begin_array();
        for (auto& d : kv.second) w.value(d);
        w.end_array().end_object();
    }
    w.end_array();
    w.kv("fileHandlesChecked", static_cast<uint64_t>(checked)).kv("denied", static_cast<uint64_t>(denied))
        .kv("skippedPipes", static_cast<uint64_t>(skipped_pipes)).kv("timeouts", static_cast<uint64_t>(timeouts))
        .kv("aborted", aborted).end_object();
}

// ------------------------------------------------------------------ Npcap adapters
// pcap_findalldevs via a dynamically loaded Npcap wpcap.dll (no build-time Npcap SDK needed).
namespace {
struct pcap_if_min {
    pcap_if_min* next;
    char* name;
    char* description;
    void* addresses;
    unsigned int flags;
};
using findalldevs_t = int (*)(pcap_if_min**, char*);
using freealldevs_t = void (*)(pcap_if_min*);
}  // namespace

void write_adapters(JsonWriter& w) {
    w.begin_object();
    auto dir = system_dir() + L"\\Npcap";
    if (!file_exists(dir + L"\\wpcap.dll")) { w.kv("error", "Npcap not installed").key("list").begin_array().end_array().end_object(); return; }
    // Make Packet.dll resolvable from the Npcap folder only for this load.
    HMODULE lib = LoadLibraryExW((dir + L"\\wpcap.dll").c_str(), nullptr, LOAD_WITH_ALTERED_SEARCH_PATH);
    if (!lib) { w.kv("error", "LoadLibrary wpcap.dll: " + win_err(GetLastError())).key("list").begin_array().end_array().end_object(); return; }
    auto f = reinterpret_cast<findalldevs_t>(reinterpret_cast<void*>(GetProcAddress(lib, "pcap_findalldevs")));
    auto fr = reinterpret_cast<freealldevs_t>(reinterpret_cast<void*>(GetProcAddress(lib, "pcap_freealldevs")));
    pcap_if_min* devs = nullptr;
    char err[512] = {};
    w.key("list").begin_array();
    std::string error;
    if (!f || !fr) error = "pcap_findalldevs not exported";
    else if (f(&devs, err) != 0) error = std::string("pcap_findalldevs: ") + err;
    else {
        for (auto* d = devs; d; d = d->next)
            w.begin_object().kv("name", d->name ? d->name : "").kv("description", d->description ? d->description : "").end_object();
        fr(devs);
    }
    w.end_array();
    if (!error.empty()) w.kv("error", error); else w.kv_null("error");
    w.end_object();
    // wpcap stays loaded until exit; the process exits right after printing.
}

}  // namespace netmon
