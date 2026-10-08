// Key extraction DLL: host-side API.
// Exported functions locate/start the target browser, inject this DLL into it
// and request the ABE master key over a named pipe.

#include "key_core.hpp"
#include <TlHelp32.h>
#include <algorithm>
#include <cstring>
#include <cwctype>
#include <mutex>
#include <map>
#include <optional>
#include <filesystem>

namespace {

    std::mutex g_callMutex;
    std::mutex g_errMutex;
    std::string g_lastError;

    void SetError(std::string msg) {
        std::lock_guard<std::mutex> lock(g_errMutex);
        g_lastError = std::move(msg);
    }

    std::wstring ToLower(std::wstring s) {
        std::transform(s.begin(), s.end(), s.begin(), ::towlower);
        return s;
    }

    const wchar_t* ExeNameForType(uint8_t type) {
        switch (type) {
            case KeyDll::TYPE_CHROME:
            case KeyDll::TYPE_CHROME_BETA: return L"chrome.exe";
            case KeyDll::TYPE_BRAVE:       return L"brave.exe";
            case KeyDll::TYPE_EDGE:        return L"msedge.exe";
            case KeyDll::TYPE_AVAST:       return L"AvastBrowser.exe";
            default:                       return L"";
        }
    }

    // Distinguishes stable Chrome from Beta (both are chrome.exe).
    bool ValidatePathForType(const std::wstring& lowerPath, uint8_t type) {
        if (type == KeyDll::TYPE_CHROME)
            return lowerPath.find(L"\\google\\chrome\\") != std::wstring::npos &&
                   lowerPath.find(L"\\google\\chrome beta\\") == std::wstring::npos;
        if (type == KeyDll::TYPE_CHROME_BETA)
            return lowerPath.find(L"\\google\\chrome beta\\") != std::wstring::npos;
        return true;
    }

    std::wstring QueryFullImagePath(HANDLE hProc) {
        DWORD size = 32768;
        std::wstring path(size, L'\0');
        if (!QueryFullProcessImageNameW(hProc, 0, path.data(), &size)) return {};
        path.resize(size);
        return path;
    }

    // Returns pid + full image path of a running target browser process,
    // preferring the root process (parent is not the same executable).
    bool FindRunningProcess(uint8_t type, DWORD& outPid, std::wstring& outPath) {
        const std::wstring exeName = ToLower(ExeNameForType(type));

        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap == INVALID_HANDLE_VALUE) return false;

        std::map<DWORD, std::wstring> pidToExe;
        std::vector<PROCESSENTRY32W> candidates;

        PROCESSENTRY32W pe{};
        pe.dwSize = sizeof(pe);
        if (Process32FirstW(snap, &pe)) {
            do {
                pidToExe[pe.th32ProcessID] = ToLower(pe.szExeFile);
                if (pidToExe[pe.th32ProcessID] == exeName)
                    candidates.push_back(pe);
            } while (Process32NextW(snap, &pe));
        }
        CloseHandle(snap);

        std::wstring fallbackPath;
        DWORD fallbackPid = 0;

        for (const auto& cand : candidates) {
            HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, cand.th32ProcessID);
            if (!hProc) continue;
            std::wstring path = QueryFullImagePath(hProc);
            CloseHandle(hProc);
            if (path.empty()) continue;

            if (!ValidatePathForType(ToLower(path), type)) continue;

            auto parentIt = pidToExe.find(cand.th32ParentProcessID);
            bool isRoot = (parentIt == pidToExe.end() || parentIt->second != exeName);

            if (isRoot) {
                outPid = cand.th32ProcessID;
                outPath = path;
                return true;
            }
            if (fallbackPid == 0) {
                fallbackPid = cand.th32ProcessID;
                fallbackPath = path;
            }
        }

        if (fallbackPid) {
            outPid = fallbackPid;
            outPath = fallbackPath;
            return true;
        }
        return false;
    }

    std::wstring RegGetSz(const std::wstring& subKey, const wchar_t* valueName) {
        DWORD type = 0, size = 0;
        const DWORD flags = RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ | RRF_SUBKEY_WOW6464KEY;
        LONG rc = RegGetValueW(HKEY_LOCAL_MACHINE, subKey.c_str(), valueName, flags,
                               &type, nullptr, &size);
        if (rc != ERROR_SUCCESS || size < sizeof(wchar_t)) return {};

        std::wstring out(size / sizeof(wchar_t), L'\0');
        rc = RegGetValueW(HKEY_LOCAL_MACHINE, subKey.c_str(), valueName, flags,
                          &type, out.data(), &size);
        if (rc != ERROR_SUCCESS) return {};
        out.resize(wcsnlen(out.c_str(), out.size()));

        if (type == REG_EXPAND_SZ) {
            std::wstring expanded(MAX_PATH * 2, L'\0');
            DWORD n = ExpandEnvironmentStringsW(out.c_str(), expanded.data(),
                                                static_cast<DWORD>(expanded.size()));
            if (n > 0 && n <= expanded.size()) {
                expanded.resize(wcsnlen(expanded.c_str(), expanded.size()));
                out = expanded;
            }
        }
        return out;
    }

    std::wstring ParseCommandPath(const std::wstring& result) {
        if (result.empty()) return {};
        size_t start = (result[0] == L'"') ? 1 : 0;
        size_t end = result.find(L'"', start);
        if (end == std::wstring::npos) end = result.find(L' ', start);
        if (end == std::wstring::npos) end = result.length();
        return result.substr(start, end - start);
    }

    // Locates the browser executable in the registry (used when not running).
    std::wstring ResolveInstalledPath(uint8_t type) {
        const std::wstring exeName = ExeNameForType(type);

        if (type != KeyDll::TYPE_CHROME && type != KeyDll::TYPE_CHROME_BETA) {
            for (const auto& key : {
                     std::wstring(L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\") + exeName,
                     std::wstring(L"SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\App Paths\\") + exeName }) {
                std::wstring path = RegGetSz(key, nullptr);
                if (!path.empty() && std::filesystem::exists(path)) return path;
            }
        }

        struct AltEntry { std::wstring key; std::wstring value; };
        std::vector<AltEntry> alt;

        switch (type) {
            case KeyDll::TYPE_CHROME:
                alt = {
                    {L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Google Chrome", L"InstallLocation"},
                    {L"SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Google Chrome", L"InstallLocation"},
                    {L"SOFTWARE\\Clients\\StartMenuInternet\\Google Chrome\\shell\\open\\command", L""},
                };
                break;
            case KeyDll::TYPE_CHROME_BETA:
                alt = {
                    {L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Google Chrome Beta", L"InstallLocation"},
                    {L"SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Google Chrome Beta", L"InstallLocation"},
                    {L"SOFTWARE\\Clients\\StartMenuInternet\\Google Chrome Beta\\shell\\open\\command", L""},
                };
                break;
            case KeyDll::TYPE_EDGE:
                alt = {
                    {L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Microsoft Edge", L"InstallLocation"},
                    {L"SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Microsoft Edge", L"InstallLocation"},
                    {L"SOFTWARE\\Clients\\StartMenuInternet\\Microsoft Edge\\shell\\open\\command", L""},
                };
                break;
            case KeyDll::TYPE_BRAVE:
                alt = {
                    {L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\BraveSoftware Brave-Browser", L"InstallLocation"},
                    {L"SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\BraveSoftware Brave-Browser", L"InstallLocation"},
                    {L"SOFTWARE\\Clients\\StartMenuInternet\\BraveSoftware Brave-Browser\\shell\\open\\command", L""},
                };
                break;
            case KeyDll::TYPE_AVAST:
                alt = {
                    {L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Avast Secure Browser", L"InstallLocation"},
                    {L"SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Avast Secure Browser", L"InstallLocation"},
                    {L"SOFTWARE\\Clients\\StartMenuInternet\\Avast Secure Browser\\shell\\open\\command", L""},
                };
                break;
            default:
                return {};
        }

        for (const auto& entry : alt) {
            std::wstring result = RegGetSz(entry.key, entry.value.empty() ? nullptr : entry.value.c_str());
            if (result.empty()) continue;

            std::wstring fullPath = entry.value.empty() ? ParseCommandPath(result)
                                                        : result + L"\\" + exeName;
            if (!fullPath.empty() && std::filesystem::exists(fullPath) &&
                ValidatePathForType(ToLower(fullPath), type)) {
                return fullPath;
            }
        }
        return {};
    }

    bool CheckArchitecture(const std::wstring& exePath) {
        HANDLE hFile = CreateFileW(exePath.c_str(), GENERIC_READ, FILE_SHARE_READ,
                                   nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hFile == INVALID_HANDLE_VALUE) return false;

        bool ok = false;
        IMAGE_DOS_HEADER dos{};
        DWORD read = 0;
        if (ReadFile(hFile, &dos, sizeof(dos), &read, nullptr) &&
            dos.e_magic == IMAGE_DOS_SIGNATURE &&
            SetFilePointer(hFile, dos.e_lfanew, nullptr, FILE_BEGIN) != INVALID_SET_FILE_POINTER) {
            IMAGE_NT_HEADERS nt{};
            if (ReadFile(hFile, &nt, sizeof(nt), &read, nullptr) &&
                nt.Signature == IMAGE_NT_SIGNATURE) {
#if defined(_M_X64)
                constexpr USHORT kHostMachine = 0x8664;
#elif defined(_M_ARM64)
                constexpr USHORT kHostMachine = 0xAA64;
#else
                constexpr USHORT kHostMachine = 0;
#endif
                ok = (nt.FileHeader.Machine == kHostMachine);
            }
        }
        CloseHandle(hFile);
        return ok;
    }

    HANDLE StartSuspendedBrowser(const std::wstring& exePath, DWORD& outPid) {
        STARTUPINFOW si{};
        si.cb = sizeof(si);
        PROCESS_INFORMATION pi{};

        if (!CreateProcessW(exePath.c_str(), nullptr, nullptr, nullptr, FALSE,
                            CREATE_SUSPENDED, nullptr, nullptr, &si, &pi)) {
            return nullptr;
        }
        CloseHandle(pi.hThread);
        outPid = pi.dwProcessId;
        return pi.hProcess;
    }

    std::wstring GetSelfDllPath() {
        std::wstring path(32768, L'\0');
        HMODULE mod = KeyDll::g_selfModule;
        if (!mod) {
            GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                               GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                               reinterpret_cast<LPCWSTR>(&GetSelfDllPath), &mod);
        }
        DWORD n = GetModuleFileNameW(mod, path.data(), static_cast<DWORD>(path.size()));
        if (n == 0) return {};
        path.resize(n);
        return path;
    }

    std::string InjectSelf(DWORD pid) {
        const std::wstring dllPath = GetSelfDllPath();
        if (dllPath.empty()) return "Cannot resolve own DLL path";

        HANDLE hProc = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
                                   PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
                                   FALSE, pid);
        if (!hProc) return "OpenProcess failed: " + std::to_string(GetLastError());

        std::string result = "";
        const SIZE_T bytes = (dllPath.size() + 1) * sizeof(wchar_t);
        void* remote = VirtualAllocEx(hProc, nullptr, bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!remote) {
            result = "VirtualAllocEx failed: " + std::to_string(GetLastError());
        } else if (!WriteProcessMemory(hProc, remote, dllPath.c_str(), bytes, nullptr)) {
            result = "WriteProcessMemory failed: " + std::to_string(GetLastError());
        } else {
            auto loadLibrary = reinterpret_cast<LPTHREAD_START_ROUTINE>(
                GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW"));
            HANDLE hThread = loadLibrary
                ? CreateRemoteThread(hProc, nullptr, 0, loadLibrary, remote, 0, nullptr)
                : nullptr;
            if (!hThread) {
                result = "CreateRemoteThread failed: " + std::to_string(GetLastError());
            } else {
                if (WaitForSingleObject(hThread, 15000) != WAIT_OBJECT_0) {
                    result = "Remote LoadLibrary thread timed out";
                } else {
                    DWORD exitCode = 0;
                    GetExitCodeThread(hThread, &exitCode);
                    if (exitCode == 0) {
                        char asciiPath[1024] = {};
                        WideCharToMultiByte(CP_ACP, 0, dllPath.c_str(), -1,
                                            asciiPath, sizeof(asciiPath), "?", nullptr);
                        result = "Remote LoadLibraryW returned NULL (dll path: " +
                                 std::string(asciiPath) + ")";
                    }
                }
                CloseHandle(hThread);
            }
        }
        if (remote) VirtualFreeEx(hProc, remote, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return result;
    }

    bool PipeTransfer(HANDLE hPipe, bool write, void* buf, DWORD len, DWORD timeoutMs,
                      DWORD* outErr = nullptr) {
        if (outErr) *outErr = 0;
        auto p = static_cast<uint8_t*>(buf);
        DWORD done = 0;
        while (done < len) {
            OVERLAPPED ov{};
            ov.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
            if (!ov.hEvent) { if (outErr) *outErr = GetLastError(); return false; }

            DWORD chunk = 0;
            BOOL ok = write
                ? WriteFile(hPipe, p + done, len - done, &chunk, &ov)
                : ReadFile(hPipe, p + done, len - done, &chunk, &ov);

            if (!ok) {
                DWORD err = GetLastError();
                if (err == ERROR_IO_PENDING) {
                    if (WaitForSingleObject(ov.hEvent, timeoutMs) != WAIT_OBJECT_0) {
                        CancelIo(hPipe);
                        if (outErr) *outErr = 258;
                        CloseHandle(ov.hEvent);
                        return false;
                    }
                    if (!GetOverlappedResult(hPipe, &ov, &chunk, FALSE)) {
                        if (outErr) *outErr = GetLastError();
                        CloseHandle(ov.hEvent);
                        return false;
                    }
                } else {
                    if (outErr) *outErr = err;
                    CloseHandle(ov.hEvent);
                    return false;
                }
            }
            CloseHandle(ov.hEvent);

            if (chunk == 0) { if (outErr) *outErr = 109; return false; }
            done += chunk;
        }
        return true;
    }

    bool ConnectAndRequest(DWORD pid, uint8_t type, uint8_t kind,
                           std::string& outPayload, int32_t& outStatus) {
        const std::wstring pipeName = KeyDll::PipeNameFor(pid);

        HANDLE hPipe = INVALID_HANDLE_VALUE;
        DWORD lastErr = 0;
        for (int i = 0; i < 100 && hPipe == INVALID_HANDLE_VALUE; ++i) {
            if (WaitNamedPipeW(pipeName.c_str(), 200)) {
                hPipe = CreateFileW(pipeName.c_str(), GENERIC_READ | GENERIC_WRITE, 0,
                                    nullptr, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, nullptr);
                if (hPipe == INVALID_HANDLE_VALUE) lastErr = GetLastError();
            } else {
                Sleep(100);
            }
        }
        if (hPipe == INVALID_HANDLE_VALUE) {
            SetError("Pipe never appeared or connect failed (last error " +
                     std::to_string(lastErr) + ")");
            return false;
        }

        KeyDll::Request req{KeyDll::PIPE_MAGIC, type, kind};
        DWORD ioErr = 0;
        bool ok = PipeTransfer(hPipe, true, &req, sizeof(req), 15000, &ioErr);
        if (!ok) {
            SetError("Pipe write failed (error " + std::to_string(ioErr) + ")");
            CloseHandle(hPipe);
            return false;
        }

        KeyDll::ResponseHeader hdr{};
        ok = PipeTransfer(hPipe, false, &hdr, sizeof(hdr), 30000, &ioErr);
        if (ok && hdr.magic != KeyDll::PIPE_MAGIC) {
            SetError("Bad response magic: " + std::to_string(hdr.magic));
            CloseHandle(hPipe);
            return false;
        }
        if (!ok) {
            SetError("Pipe header read failed (error " + std::to_string(ioErr) + ")");
            CloseHandle(hPipe);
            return false;
        }

        std::string payload(hdr.length, '\0');
        if (hdr.length > 0) {
            ok = PipeTransfer(hPipe, false, payload.data(), hdr.length, 30000, &ioErr);
            if (!ok) {
                SetError("Pipe payload read failed: status=" + std::to_string(hdr.status) +
                         " length=" + std::to_string(hdr.length) +
                         " error=" + std::to_string(ioErr));
                CloseHandle(hPipe);
                return false;
            }
        }

        CloseHandle(hPipe);
        outStatus = hdr.status;
        outPayload = std::move(payload);
        return true;
    }

    int HostGetKey(uint8_t type, uint8_t kind, char* out, int cap) {
        if (!out || cap < 66) {
            SetError("Buffer too small (need at least 66 bytes)");
            return 0;
        }
        out[0] = '\0';

        std::lock_guard<std::mutex> lock(g_callMutex);

        std::wstring exePath;
        DWORD pid = 0;
        HANDLE hNewProc = nullptr;
        bool created = false;

        if (!FindRunningProcess(type, pid, exePath)) {
            exePath = ResolveInstalledPath(type);
            if (exePath.empty()) {
                SetError("Target browser is not running and could not be located");
                return -1;
            }
            if (!CheckArchitecture(exePath)) {
                SetError("Architecture mismatch: use the DLL matching the browser (x64/ARM64)");
                return -2;
            }
            hNewProc = StartSuspendedBrowser(exePath, pid);
            if (!hNewProc) {
                SetError("Failed to start browser process, error " + std::to_string(GetLastError()));
                return -1;
            }
            created = true;
        } else if (!CheckArchitecture(exePath)) {
            SetError("Architecture mismatch: use the DLL matching the browser (x64/ARM64)");
            return -2;
        }

        auto fail = [&](int code, std::string msg) -> int {
            if (created && hNewProc) {
                TerminateProcess(hNewProc, 1);
                WaitForSingleObject(hNewProc, 3000);
                CloseHandle(hNewProc);
            }
            SetError(std::move(msg));
            return code;
        };

        std::string injectErr = InjectSelf(pid);
        if (!injectErr.empty()) {
            return fail(-3, "Injection failed: " + injectErr);
        }

        std::string payload;
        int32_t status = -1;
        if (!ConnectAndRequest(pid, type, kind, payload, status)) {
            // ConnectAndRequest already set a detailed error message
            if (created && hNewProc) {
                TerminateProcess(hNewProc, 1);
                WaitForSingleObject(hNewProc, 3000);
                CloseHandle(hNewProc);
            }
            return -4;
        }

        if (created && hNewProc) {
            TerminateProcess(hNewProc, 0);
            WaitForSingleObject(hNewProc, 3000);
            CloseHandle(hNewProc);
        }

        if (status != 0) {
            SetError(payload.empty() ? "Key extraction failed inside the browser" : payload);
            return -5;
        }

        if (payload.size() + 1 > static_cast<size_t>(cap)) {
            SetError("Buffer too small for key");
            return 0;
        }
        memcpy(out, payload.c_str(), payload.size() + 1);
        return 1;
    }

}

extern "C" {

__declspec(dllexport) int GetChromeKeyHex(char* out, int cap) {
    return HostGetKey(KeyDll::TYPE_CHROME, KeyDll::KIND_MAIN, out, cap);
}

__declspec(dllexport) int GetChromeBetaKeyHex(char* out, int cap) {
    return HostGetKey(KeyDll::TYPE_CHROME_BETA, KeyDll::KIND_MAIN, out, cap);
}

__declspec(dllexport) int GetBraveKeyHex(char* out, int cap) {
    return HostGetKey(KeyDll::TYPE_BRAVE, KeyDll::KIND_MAIN, out, cap);
}

__declspec(dllexport) int GetEdgeKeyHex(char* out, int cap) {
    return HostGetKey(KeyDll::TYPE_EDGE, KeyDll::KIND_MAIN, out, cap);
}

__declspec(dllexport) int GetEdgeCopilotKeyHex(char* out, int cap) {
    return HostGetKey(KeyDll::TYPE_EDGE, KeyDll::KIND_ASTER, out, cap);
}

__declspec(dllexport) int GetAvastKeyHex(char* out, int cap) {
    return HostGetKey(KeyDll::TYPE_AVAST, KeyDll::KIND_MAIN, out, cap);
}

__declspec(dllexport) int GetLastKeyError(char* out, int cap) {
    if (!out || cap <= 0) return 0;
    std::string err;
    {
        std::lock_guard<std::mutex> lock(g_errMutex);
        err = g_lastError;
    }
    size_t n = (std::min)(err.size(), static_cast<size_t>(cap - 1));
    memcpy(out, err.data(), n);
    out[n] = '\0';
    return static_cast<int>(n);
}

}
