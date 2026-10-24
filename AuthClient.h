#pragma once
#include <windows.h>
#include <wininet.h>
#include <string>
#include <vector>
#include <iostream>

#pragma comment(lib, "wininet.lib")

namespace SimpleAuth
{
    static const char* API_HOST = "biosuuid.vercel.app"; // NO HTTPS://
    static const INTERNET_PORT API_PORT = INTERNET_DEFAULT_HTTPS_PORT;
    static const char* API_PATH = "/api/verify";

    static const char* OWNER_ID = "e4b3c2a1-8765-4321-90ab-cdef12345678";
    static const char* SECRET_KEY = "bloody_sec_9f8e7d6c5b4a39281706f5e4d3c2b1a";

    inline std::string GetSystemUUID()
    {
        const DWORD RSMB = 0x52534D42;
        DWORD size = GetSystemFirmwareTable(RSMB, 0, NULL, 0);
        if (size == 0) return "UNKNOWN";

        std::vector<BYTE> buffer(size);
        if (GetSystemFirmwareTable(RSMB, 0, buffer.data(), size) == 0) return "UNKNOWN";

        size_t offset = 8;
        while (offset + 4 < size)
        {
            BYTE type = buffer[offset];
            BYTE len = buffer[offset + 1];

            if (type == 1 && len >= 0x19)
            {
                const BYTE* u = &buffer[offset + 8];
                char uuidStr[64] = { 0 };
                wsprintfA(uuidStr, "%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
                    u[3], u[2], u[1], u[0], u[5], u[4], u[7], u[6], u[8], u[9], u[10], u[11], u[12], u[13], u[14], u[15]);
                return std::string(uuidStr);
            }

            offset += len;
            while (offset + 1 < size && !(buffer[offset] == 0 && buffer[offset + 1] == 0)) offset++;
            offset += 2;
        }
        return "UNKNOWN";
    }

    inline std::string ExtractJsonField(const std::string& json, const std::string& field)
    {
        std::string pattern = "\"" + field + "\":\"";
        size_t start = json.find(pattern);
        if (start != std::string::npos)
        {
            start += pattern.length();
            size_t end = json.find("\"", start);
            if (end != std::string::npos) return json.substr(start, end - start);
        }
        return "";
    }

    inline bool Verify()
    {
        bool authorized = false;
        std::string reason = "Cannot connect to Auth Server";
        std::string systemUuid = "UNKNOWN";

        __try
        {
            systemUuid = GetSystemUUID();

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

                    DWORD dwFlags = INTERNET_FLAG_SECURE | INTERNET_FLAG_NO_CACHE_WRITE |
                        INTERNET_FLAG_RELOAD | INTERNET_FLAG_PRAGMA_NOCACHE |
                        INTERNET_FLAG_IGNORE_CERT_CN_INVALID | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID;

                    HINTERNET hRequest = HttpOpenRequestA(hConnect, "GET", fullPath.c_str(), NULL, NULL, NULL, dwFlags, 0);
                    if (hRequest)
                    {
                        if (HttpSendRequestA(hRequest, NULL, 0, NULL, 0))
                        {
                            std::string response;
                            char buffer[4096];
                            DWORD bytesRead = 0;

                            while (InternetReadFile(hRequest, buffer, sizeof(buffer) - 1, &bytesRead) && bytesRead > 0)
                                response.append(buffer, bytesRead);

                            if (response.find("\"status\":1") != std::string::npos || response.find("\"status\": 1") != std::string::npos)
                            {
                                authorized = true;
                            }
                            else
                            {
                                std::string serverMsg = ExtractJsonField(response, "message");
                                reason = serverMsg.empty() ? ("Server Response: " + response) : serverMsg;
                            }
                        }
                        else reason = "HttpSendRequest failed (Error " + std::to_string(GetLastError()) + ")";
                        InternetCloseHandle(hRequest);
                    }
                    InternetCloseHandle(hConnect);
                }
                InternetCloseHandle(hInternet);
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) { reason = "Internal error during verification"; }

        if (!authorized)
        {
            std::string msg = "authorization failed\nUUID: " + systemUuid + "\nReason: " + reason;
            MessageBoxA(NULL, msg.c_str(), "Bloody Auth System", MB_OK | MB_ICONERROR);
        }
        return authorized;
    }

    inline DWORD WINAPI _AuthThread(LPVOID) {
        if (!Verify()) ExitProcess(0);
        return 0;
    }

    inline void Protect() {
        if (!Verify()) ExitProcess(0);
    }

    // Call this in DllMain(DLL_PROCESS_ATTACH)
    inline void ProtectDLL(HMODULE hModule = NULL) {
        HANDLE hThread = CreateThread(NULL, 0, _AuthThread, NULL, 0, NULL);
        if (hThread) CloseHandle(hThread);
        else if (!Verify()) ExitProcess(0);
    }
}
