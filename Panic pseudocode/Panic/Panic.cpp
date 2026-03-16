/*
 * Panic - by meLdozy (wh1tness)
 * Restored source code from IDA pseudocode
 *
 * Build: g++ -std=c++17 panic.cpp -o panic.exe -lole32 -loleaut32
 * Or MSVC: cl /std:c++17 panic.cpp /link
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include <shlobj.h>
#include <iostream>
#include <filesystem>
#include <string>
#include <vector>
#include <algorithm>

namespace fs = std::filesystem;

// ─────────────────────────────────────────────
//  Forward declarations
// ─────────────────────────────────────────────
static void clearAll();
static void autoClosePrograms(const std::vector<std::wstring>& targets);
static void backFolders(const fs::path& src, const fs::path& dst);
static std::string getUserSID();
static void killProcessByName(const std::wstring& name);

// ─────────────────────────────────────────────
//  sub_140003500  —  "Clear all"
//  Clears registry traces + temp artefacts,
//  also runs dynamic REG commands keyed to
//  the current user's SID (extracted from
//  HKCU path under HKEY_USERS).
// ─────────────────────────────────────────────
static void clearAll()
{
    system("COLOR A");

    // ── Static registry / file cleanups ──────────────────────────────────
    system("REG DELETE \"HKEY_CURRENT_USER\\Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\MuiCache\" /va /f");
    system("REG DELETE \"HKEY_CURRENT_USER\\Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU\" /f");
    system("REG DELETE \"HKEY_CURRENT_USER\\Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\Bags\" /f");
    system("REG DELETE \"HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\Shell\\BagMRU\" /f");
    system("REG DELETE \"HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\Shell\\Bags\" /f");
    system("REG DELETE \"HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU\" /va /f");
    system("REG DELETE \"HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\FirstFolder\" /va /f");
    system("REG DELETE \"HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\LastVisitedPidlMRU\" /va /f");
    system("REG DELETE \"HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\LastVisitedPidlMRULegacy\" /va /f");
    system("REG DELETE \"HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\OpenSavePidlMRU\" /f");
    system("REG ADD    \"HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\OpenSavePidlMRU\"");
    system("REG DELETE \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCompatCache\" /va /f");
    system("REG DELETE \"HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Control\\Session Manager\\AppCompatCache\" /va /f");
    system("REG DELETE \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\RADAR\\HeapLeakDetection\\DiagnosedApplications\" /f");
    system("REG ADD    \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\RADAR\\HeapLeakDetection\\DiagnosedApplications\"");
    system("DEL /f /q %APPDATA%\\Microsoft\\Windows\\Recent\\*.*");
    system("DEL /f /q %APPDATA%\\Microsoft\\Windows\\Recent\\CustomDestinations\\*.*");
    system("DEL /f /q %APPDATA%\\Microsoft\\Windows\\Recent\\AutomaticDestinations\\*.*");
    system("DEL /f /q %systemroot%\\Panther\\*.*");
    system("DEL /f /q %systemroot%\\appcompat\\Programs\\*.txt");
    system("DEL /f /q %systemroot%\\appcompat\\Programs\\*.xml");
    system("DEL /f /q %systemroot%\\appcompat\\Programs\\Install\\*.txt");
    system("DEL /f /q %systemroot%\\appcompat\\Programs\\Install\\*.xml");

    // ── Dynamic commands that use the SID ────────────────────────────────
    // Get current username, then find its SID suffix under HKEY_USERS
    CHAR  username[128] = {};
    DWORD cbUser = sizeof(username);
    GetUserNameA(username, &cbUser);

    // Extract the part after the first backslash (domain\user → user)
    std::string user(username);
    auto slash = user.find('\\');
    std::string userPart = (slash != std::string::npos) ? user.substr(slash + 1) : user;

    // Enumerate HKEY_USERS sub-keys to find the SID that matches this user
    std::string sid;
    {
        HKEY hku = nullptr;
        if (RegOpenKeyExA(HKEY_USERS, nullptr, 0, KEY_READ, &hku) == ERROR_SUCCESS)
        {
            char   subkey[256];
            DWORD  idx = 0, cchSubkey;
            while (true)
            {
                cchSubkey = sizeof(subkey);
                if (RegEnumKeyExA(hku, idx++, subkey, &cchSubkey,
                    nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS)
                    break;
                // A user SID looks like S-1-5-21-...
                std::string sk(subkey);
                if (sk.rfind("S-1-5-21", 0) == 0 && sk.find('_') == std::string::npos)
                {
                    sid = sk;
                    break;
                }
            }
            RegCloseKey(hku);
        }
    }

    if (!sid.empty())
    {
        // REG DELETE "HKEY_USERS\<SID>"  (the commands seen in the pseudocode)
        std::string cmdDel1 = "REG DELETE \"HKEY_USERS\\" + sid + "\" /va /f";
        std::string cmdAdd1 = "REG ADD    \"HKEY_USERS\\" + sid + "\"";

        system(("REG DELETE \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\bam\\UserSettings\\" + sid + "\" /va /f").c_str());
        system(("REG DELETE \"HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Services\\bam\\UserSettings\\" + sid + "\" /va /f").c_str());
        system(cmdDel1.c_str());
        system(cmdDel1.c_str());   // called twice in the original
        system(cmdAdd1.c_str());
    }
}

// ─────────────────────────────────────────────
//  sub_140003180  —  kill a process by name
// ─────────────────────────────────────────────
static void killProcessByName(const std::wstring& name)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return;

    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);

    if (!Process32FirstW(snap, &pe))
    {
        CloseHandle(snap);
        return;
    }

    do
    {
        if (_wcsicmp(pe.szExeFile, name.c_str()) == 0)
        {
            HANDLE hProc = OpenProcess(PROCESS_TERMINATE, FALSE, pe.th32ProcessID);
            if (hProc)
            {
                TerminateProcess(hProc, 0);
                CloseHandle(hProc);
            }
        }
    } while (Process32NextW(snap, &pe));

    CloseHandle(snap);
}

// ─────────────────────────────────────────────
//  sub_140003180 (full)  —  "Auto-closing programs"
//  Keeps scanning until none of the target
//  processes are alive (with a 1-second pause
//  between sweeps, matching sub_140006B70).
// ─────────────────────────────────────────────
static void autoClosePrograms(const std::vector<std::wstring>& targets)
{
    bool found = true;
    while (found)
    {
        found = false;

        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap == INVALID_HANDLE_VALUE)
            break;

        PROCESSENTRY32W pe{};
        pe.dwSize = sizeof(pe);

        if (Process32FirstW(snap, &pe))
        {
            do
            {
                for (const auto& t : targets)
                {
                    if (_wcsicmp(pe.szExeFile, t.c_str()) == 0)
                    {
                        HANDLE hProc = OpenProcess(PROCESS_TERMINATE, FALSE, pe.th32ProcessID);
                        if (hProc)
                        {
                            TerminateProcess(hProc, 0);
                            CloseHandle(hProc);
                            found = true;
                        }
                    }
                }
            } while (Process32NextW(snap, &pe));
        }

        CloseHandle(snap);

        if (found)
            Sleep(1000);   // sub_140006B70 — pause between retries
    }
}

// ─────────────────────────────────────────────
//  "Back folders"  (option 3)
//  Iterates entries in `src`, strips embedded
//  null bytes (0x30 = '0' padding from option 1)
//  from the name, then renames into `dst\name`.
// ─────────────────────────────────────────────
static void backFolders(const fs::path& src, const fs::path& dst)
{
    std::error_code ec;

    for (const auto& entry : fs::directory_iterator(src, ec))
    {
        if (ec)
            break;

        // Get just the filename (leaf) part — mirrors sub_140001BF0 logic
        std::string name = entry.path().filename().string();

        // Remove embedded '0' padding bytes inserted by option 1
        // (the pseudocode removes char 0x30 which is ASCII '0')
        name.erase(std::remove(name.begin(), name.end(), '\0'), name.end());

        if (name.empty())
            continue;

        fs::path target = dst / name;

        std::error_code renameEc;
        fs::rename(entry.path(), target, renameEc);

        if (!renameEc)
            std::cout << "Moved: " << name << "\n";
    }
}

// ─────────────────────────────────────────────
//  Option 1 helper  —  move entries from src
//  into dst appending backslash suffix.
//  Mirrors the loop in main() for choice "1".
// ─────────────────────────────────────────────
static void moveEntries(const fs::path& src, const fs::path& dst)
{
    std::error_code ec;

    for (const auto& entry : fs::directory_iterator(src, ec))
    {
        if (ec)
            break;

        std::string name = entry.path().filename().string();

        // Build padded name: each char followed by '0' byte
        // (this is what the pseudocode builds in the v172 buffer)
        std::string padded;
        padded.reserve(name.size() * 2);
        for (char c : name)
        {
            padded += c;
            padded += '\0';
        }

        fs::path target = dst / name;

        std::error_code renameEc;
        fs::rename(entry.path(), target, renameEc);

        if (!renameEc)
            std::cout << "Moved: " << name << "\n";
    }
}

// ─────────────────────────────────────────────
//  Entry point
// ─────────────────────────────────────────────
int main()
{
    // ── Console setup (sub_1400046A0 / sub_140002F30) ────────────────────
    SetConsoleTitleW(L"Panic");
    SetConsoleCP(1251);
    SetConsoleOutputCP(1251);

    // ── Resolve %USERPROFILE% ────────────────────────────────────────────
    char* profileEnv = nullptr;
    size_t profileLen = 0;
    _dupenv_s(&profileEnv, &profileLen, "USERPROFILE");

    fs::path userProfile(profileEnv ? profileEnv : "C:\\Users\\Default");
    free(profileEnv);

    // src  = USERPROFILE\          (used by option 1 & 3)
    // dst  = USERPROFILE\          (same root — rename within profile)
    fs::path srcPath = userProfile;
    fs::path dstPath = userProfile;

    // ── Initial display ──────────────────────────────────────────────────
    setlocale(LC_ALL, "ru");
    system("COLOR A");
    system("CLS");

    std::cout << "  _____            _\n";
    std::cout << " |  __ \\          (_)\n";
    std::cout << " | |__) |_ _ _ __  _  ___\n";
    std::cout << " |  ___/ _` | '_ \\| |/ __| recode by https://t.me/+5EHmo7zE-KBlYzMy\n";
    std::cout << " | |  | (_| | | | | | (__\n";
    std::cout << " |_|   \\__,_|_| |_|_|\\___|\n";
    std::cout << "1. Clear all\n";
    std::cout << "2. Auto-closing programs\n";
    std::cout << "3. Back folders\n";
    std::cout << "Enter choice: ";

    std::string choice;
    std::cin >> choice;

    // ── Option 1 : Clear all ─────────────────────────────────────────────
    if (choice == "1")
    {
        clearAll();
        moveEntries(srcPath, dstPath);
        system("ECHO Successfully");
        system("PAUSE");
        return main();
    }

    // ── Option 2 : Auto-closing programs ────────────────────────────────
    if (choice == "2")
    {
        std::cout << "\nClosing target processes...\n";

        std::vector<std::wstring> targets = {
            L"lastactivityview.exe",
            L"everything.exe",
            L"shellbag_analyzer_cleaner.exe",
            L"SystemSettings.exe"
        };

        autoClosePrograms(targets);
        system("PAUSE");
        return main();
    }

    // ── Option 3 : Back folders ──────────────────────────────────────────
    if (choice == "3")
    {
        backFolders(srcPath, dstPath);
        std::cout << "successfully.\n";
        system("PAUSE");
        return main();
    }

    return 0;
}