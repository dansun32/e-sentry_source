using System.ComponentModel;
using System.Runtime.InteropServices;
using NetmonEtw.Core;

namespace NetmonEtw;

/// <summary>Read-only Service Control Manager access (EnumServicesStatusEx + QueryServiceConfig).</summary>
internal static class Scm
{
    private const uint SC_MANAGER_CONNECT = 0x0001, SC_MANAGER_ENUMERATE_SERVICE = 0x0004;
    private const uint SERVICE_QUERY_CONFIG = 0x0001;
    private const uint SERVICE_WIN32 = 0x30, SERVICE_WIN32_SHARE_PROCESS = 0x20, SERVICE_STATE_ALL = 3;
    private const int SC_ENUM_PROCESS_INFO = 0;
    private const int ERROR_MORE_DATA = 234, ERROR_INSUFFICIENT_BUFFER = 122;

    [StructLayout(LayoutKind.Sequential)]
    private struct SERVICE_STATUS_PROCESS
    {
        public uint dwServiceType, dwCurrentState, dwControlsAccepted, dwWin32ExitCode,
                    dwServiceSpecificExitCode, dwCheckPoint, dwWaitHint, dwProcessId, dwServiceFlags;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct ENUM_SERVICE_STATUS_PROCESS
    {
        public IntPtr lpServiceName, lpDisplayName;
        public SERVICE_STATUS_PROCESS ServiceStatusProcess;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct QUERY_SERVICE_CONFIG
    {
        public uint dwServiceType, dwStartType, dwErrorControl;
        public IntPtr lpBinaryPathName, lpLoadOrderGroup;
        public uint dwTagId;
        public IntPtr lpDependencies, lpServiceStartName, lpDisplayName;
    }

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr OpenSCManagerW(string? machine, string? db, uint access);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr OpenServiceW(IntPtr scm, string name, uint access);
    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool CloseServiceHandle(IntPtr h);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool EnumServicesStatusExW(IntPtr scm, int infoLevel, uint serviceType, uint state,
        IntPtr buf, uint bufSize, out uint needed, out uint returned, ref uint resume, string? group);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool QueryServiceConfigW(IntPtr svc, IntPtr buf, uint size, out uint needed);

    // Start types rarely change; cache them (QueryServiceConfig per service is the slow part).
    private static readonly Dictionary<string, (string Type, DateTime At)> StartCache = new(StringComparer.OrdinalIgnoreCase);
    private static readonly TimeSpan StartTtl = TimeSpan.FromSeconds(30);

    public static List<ServiceInfo> Enumerate()
    {
        IntPtr scm = OpenSCManagerW(null, null, SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE);
        if (scm == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error(), "OpenSCManager");
        try
        {
            var list = new List<ServiceInfo>();
            uint resume = 0, size = 64 * 1024;
            while (true)
            {
                IntPtr buf = Marshal.AllocHGlobal((int)size);
                try
                {
                    bool ok = EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL,
                                                    buf, size, out uint needed, out uint count, ref resume, null);
                    int err = ok ? 0 : Marshal.GetLastWin32Error();
                    if (!ok && err != ERROR_MORE_DATA) throw new Win32Exception(err, "EnumServicesStatusEx");
                    int stride = Marshal.SizeOf<ENUM_SERVICE_STATUS_PROCESS>();
                    for (int i = 0; i < count; i++)
                    {
                        var e = Marshal.PtrToStructure<ENUM_SERVICE_STATUS_PROCESS>(buf + i * stride);
                        string name = Marshal.PtrToStringUni(e.lpServiceName) ?? "";
                        string disp = Marshal.PtrToStringUni(e.lpDisplayName) ?? name;
                        var st = e.ServiceStatusProcess;
                        list.Add(new ServiceInfo(name, disp, Attribution.StateName(st.dwCurrentState),
                            StartType(scm, name), st.dwCurrentState == 1 ? 0 : (int)st.dwProcessId,
                            (st.dwServiceType & SERVICE_WIN32_SHARE_PROCESS) != 0));
                    }
                    if (ok) break;
                    if (needed > size) size = needed + 4096;
                }
                finally { Marshal.FreeHGlobal(buf); }
            }
            return list;
        }
        finally { CloseServiceHandle(scm); }
    }

    private static string StartType(IntPtr scm, string name)
    {
        if (StartCache.TryGetValue(name, out var c) && DateTime.UtcNow - c.At < StartTtl) return c.Type;
        string result = "unknown";
        IntPtr svc = OpenServiceW(scm, name, SERVICE_QUERY_CONFIG);
        if (svc != IntPtr.Zero)
        {
            try
            {
                QueryServiceConfigW(svc, IntPtr.Zero, 0, out uint needed);
                if (Marshal.GetLastWin32Error() == ERROR_INSUFFICIENT_BUFFER && needed > 0 && needed < 1 << 20)
                {
                    IntPtr buf = Marshal.AllocHGlobal((int)needed);
                    try
                    {
                        if (QueryServiceConfigW(svc, buf, needed, out _))
                            result = Attribution.StartTypeName(Marshal.PtrToStructure<QUERY_SERVICE_CONFIG>(buf).dwStartType);
                    }
                    finally { Marshal.FreeHGlobal(buf); }
                }
            }
            finally { CloseServiceHandle(svc); }
        }
        StartCache[name] = (result, DateTime.UtcNow);
        return result;
    }
}
