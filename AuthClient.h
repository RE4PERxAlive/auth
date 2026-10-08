#pragma once
#include <windows.h>
#include <wininet.h>
#include <string>
#include <vector>

#pragma comment(lib, "wininet.lib")

namespace SimpleAuth
{
    // =========================================================================
    // CONFIGURATION - Bloody Auth Server Credentials
    // =========================================================================
    inline const char* API_HOST   = "127.0.0.1";
    inline const INTERNET_PORT API_PORT = 8080;
    inline const char* API_PATH   = "/verify";

    inline const char* OWNER_ID   = "e4b3c2a1-8765-4321-90ab-cdef12345678";
    inline const char* SECRET_KEY = "bloody_sec_9f8e7d6c5b4a39281706f5e4d3c2b1a";

    // =========================================================================
    // HARDWARE SYSTEM UUID EXTRACTION (Native SMBIOS Firmware Table)
    // Matches Win32_ComputerSystemProduct UUID on Windows
    // =========================================================================
    inline std::string GetSystemUUID()
    {
        const DWORD RSMB = 0x52534D42; // 'RSMB'
        DWORD size = GetSystemFirmwareTable(RSMB, 0, NULL, 0);
        if (size == 0) return "UNKNOWN";

        std::vector<BYTE> buffer(size);
        if (GetSystemFirmwareTable(RSMB, 0, buffer.data(), size) == 0) return "UNKNOWN";

        size_t offset = 8; // Skip RawSMBIOSData header
        while (offset + 4 < size)
        {
            BYTE type = buffer[offset];
            BYTE len = buffer[offset + 1];

            if (type == 1 && len >= 0x19) // Type 1: System Information
            {
                const BYTE* u = &buffer[offset + 8];
                char uuidStr[64] = { 0 };
                wsprintfA(uuidStr, "%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
                    u[3], u[2], u[1], u[0],
                    u[5], u[4],
                    u[7], u[6],
                    u[8], u[9],
                    u[10], u[11], u[12], u[13], u[14], u[15]);
                return std::string(uuidStr);
            }

            offset += len;
            while (offset + 1 < size && !(buffer[offset] == 0 && buffer[offset + 1] == 0))
            {
                offset++;
            }
            offset += 2;
        }

        // Fallback to computer name
        char compName[MAX_COMPUTERNAME_LENGTH + 1] = { 0 };
        DWORD cSize = sizeof(compName);
        GetComputerNameA(compName, &cSize);
        return std::string(compName);
    }

    // Helper to extract JSON string value
    inline std::string ExtractJsonField(const std::string& json, const std::string& field)
    {
        std::string pattern = "\"" + field + "\":\"";
        size_t start = json.find(pattern);
        if (start != std::string::npos)
        {
            start += pattern.length();
            size_t end = json.find("\"", start);
            if (end != std::string::npos)
            {
                return json.substr(start, end - start);
            }
        }
        return "";
    }

    // =========================================================================
    // MAIN VERIFICATION CALL
    // Usage in main(): if (!SimpleAuth::Verify()) return 0;
    // Checks if the client's System UUID is registered & active on the website!
    // =========================================================================
    inline bool Verify()
    {
        bool authorized = false;
        std::string reason = "Cannot connect to Auth Server (is server running?)";
        std::string systemUuid = GetSystemUUID();

        HINTERNET hInternet = InternetOpenA("BloodyAuthClient/3.0", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
        if (hInternet)
        {
            HINTERNET hConnect = InternetConnectA(hInternet, API_HOST, API_PORT, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
            if (hConnect)
            {
                std::string fullPath = std::string(API_PATH) +
                    "?owner_id=" + OWNER_ID +
                    "&secret_key=" + SECRET_KEY +
                    "&system_uuid=" + systemUuid;

                HINTERNET hRequest = HttpOpenRequestA(hConnect, "GET", fullPath.c_str(), NULL, NULL, NULL,
                    INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_RELOAD | INTERNET_FLAG_PRAGMA_NOCACHE, 0);

                if (hRequest)
                {
                    if (HttpSendRequestA(hRequest, NULL, 0, NULL, 0))
                    {
                        char buffer[2048] = { 0 };
                        DWORD bytesRead = 0;
                        if (InternetReadFile(hRequest, buffer, sizeof(buffer) - 1, &bytesRead) && bytesRead > 0)
                        {
                            std::string response(buffer, bytesRead);

                            if (response.find("\"status\":1") != std::string::npos ||
                                response.find("\"status\": 1") != std::string::npos)
                            {
                                authorized = true;
                            }
                            else
                            {
                                std::string serverMsg = ExtractJsonField(response, "message");
                                reason = serverMsg.empty() ? "System UUID is not authorized" : serverMsg;
                            }
                        }
                    }
                    else
                    {
                        DWORD err = GetLastError();
                        reason = "HttpSendRequest failed (Error " + std::to_string(err) + ")";
                    }
                    InternetCloseHandle(hRequest);
                }
                InternetCloseHandle(hConnect);
            }
            InternetCloseHandle(hInternet);
        }

        if (!authorized)
        {
            std::string alertText = "authorization failed\n\nSystem UUID: " + systemUuid + "\nReason: " + reason;
            MessageBoxA(NULL, alertText.c_str(), "Bloody Auth Guard", MB_OK | MB_ICONERROR);
        }

        return authorized;
    }
}
