#pragma once
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <objbase.h>  // StringFromGUID2

#include <string>

namespace netmon {

inline std::string utf8(const wchar_t* w, int len = -1) {
    if (!w) return {};
    if (len == 0) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, w, len, nullptr, 0, nullptr, nullptr);
    if (n <= 0) return {};
    std::string s(static_cast<size_t>(n), '\0');
    WideCharToMultiByte(CP_UTF8, 0, w, len, &s[0], n, nullptr, nullptr);
    if (len == -1 && !s.empty() && s.back() == '\0') s.pop_back();
    return s;
}
inline std::string utf8(const std::wstring& w) { return utf8(w.c_str(), static_cast<int>(w.size())); }

inline std::string guid_str(const GUID& g) {
    wchar_t b[64] = {};
    StringFromGUID2(g, b, 64);
    return utf8(b);
}

inline std::string win_err(DWORD e) {
    wchar_t* msg = nullptr;
    FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, nullptr, e,
                   0, reinterpret_cast<LPWSTR>(&msg), 0, nullptr);
    std::string s = msg ? utf8(msg) : std::string();
    if (msg) LocalFree(msg);
    while (!s.empty() && (s.back() == '\n' || s.back() == '\r' || s.back() == ' ' || s.back() == '.')) s.pop_back();
    return "error " + std::to_string(e) + (s.empty() ? "" : ": " + s);
}

inline std::string process_image(DWORD pid, std::string* full = nullptr) {
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return pid == 4 ? "System" : "pid " + std::to_string(pid);
    wchar_t buf[MAX_PATH * 2];
    DWORD n = MAX_PATH * 2;
    std::string r = "pid " + std::to_string(pid);
    if (QueryFullProcessImageNameW(h, 0, buf, &n)) {
        std::wstring p(buf, n);
        if (full) *full = utf8(p);
        auto slash = p.find_last_of(L"\\/");
        r = utf8(slash == std::wstring::npos ? p : p.substr(slash + 1));
    }
    CloseHandle(h);
    return r;
}

}  // namespace netmon
