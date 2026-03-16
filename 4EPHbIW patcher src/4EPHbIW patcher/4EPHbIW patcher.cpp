#include <windows.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <iomanip>
#include <sstream>
#include <cstring>

static std::string hex_bytes(const uint8_t* p, size_t n) {
    std::ostringstream ss;
    for (size_t i = 0; i < n; i++) {
        if (i) ss << ' ';
        ss << std::hex << std::uppercase << std::setw(2) << std::setfill('0') << (int)p[i];
    }
    return ss.str();
}

static size_t find_pattern(const std::vector<uint8_t>& file,
    const std::vector<uint8_t>& pat,
    size_t start = 0)
{
    if (pat.size() > file.size()) return SIZE_MAX;
    size_t limit = file.size() - pat.size();
    for (size_t i = start; i <= limit; i++)
        if (memcmp(file.data() + i, pat.data(), pat.size()) == 0)
            return i;
    return SIZE_MAX;
}

static bool patch_string(std::vector<uint8_t>& file,
    const char* label,
    const char* oldstr,
    const char* newstr)
{
    size_t oldlen = strlen(oldstr);
    size_t newlen = strlen(newstr);

    if (newlen > oldlen) {
        std::cout << "     " << label << ": new string too long ("
            << newlen << " > " << oldlen << "), skipping\n";
        return false;
    }

    std::vector<uint8_t> pat(oldstr, oldstr + oldlen);
    size_t off = find_pattern(file, pat);
    if (off == SIZE_MAX) {
        std::cout << "     " << label << ": not found\n";
        return false;
    }

    for (size_t i = 0; i < oldlen; i++)
        file[off + i] = (i < newlen) ? (uint8_t)newstr[i] : 0x00;

    std::cout << "     " << label << " at 0x" << std::hex << off << "\n"
        << "        \"" << oldstr << "\"\n"
        << "     >>> \"" << newstr << "\"\n";
    return true;
}

int run()
{
    std::string path;
    std::cout << "Path to .exe: ";
    std::getline(std::cin, path);
    while (!path.empty() && (path.front() == '"' || path.front() == ' ')) path.erase(path.begin());
    while (!path.empty() && (path.back() == '"' || path.back() == ' ')) path.pop_back();

    std::ifstream fin(path, std::ios::binary);
    if (!fin) { std::cerr << " Cannot open: " << path << "\n"; return 1; }
    std::vector<uint8_t> data(
        (std::istreambuf_iterator<char>(fin)),
        std::istreambuf_iterator<char>());
    fin.close();

    if (data.size() < 2 || data[0] != 'M' || data[1] != 'Z') {
        std::cerr << " Not a valid PE file.\n"; return 1;
    }
    std::cout << " Loaded " << std::dec << data.size() << " bytes.\n\n";

    int ok = 0;

    // PATCH 1 - Login: success bool check (near JZ >>> 6x NOP)
    // 48 8B 50 08 = mov rdx,[rax+8]
    // 80 3A 00    = cmp byte ptr [rdx],0
    // 0F 84 xx xx xx xx = JZ near
    {
        uint8_t search[] = {
            0x48, 0x8B, 0x50, 0x08,
            0x80, 0x3A, 0x00,
            0x0F, 0x84
        };
        std::vector<uint8_t> pat(search, search + sizeof(search));
        size_t base = find_pattern(data, pat);
        if (base == SIZE_MAX) {
            std::cout << " Patch 1: pattern not found\n\n";
        }
        else {
            size_t jz_off = base + 7;
            std::cout << " Patch 1 - Login success bool check\n"
                << "     Found at file offset 0x" << std::hex << base << "\n"
                << "     JZ near at offset 0x" << jz_off << "\n"
                << "     Bytes: " << hex_bytes(data.data() + jz_off, 6) << "\n";
            if (data[jz_off] == 0x0F && data[jz_off + 1] == 0x84) {
                for (int i = 0; i < 6; i++) data[jz_off + i] = 0x90;
                std::cout << "     NOPed 6 bytes (JZ near removed)\n\n";
                ok++;
            }
            else {
                std::cout << "     Unexpected bytes, skipping\n\n";
            }
        }
    }

    // PATCH 2 - doRequest: HMAC signature check
    // 84 C0 = test al,al
    // 0F 84 xx xx xx xx = JZ near >>> NOP x6
    // fallback: 74 xx = JZ short >>> EB
    {
        size_t from = data.size() / 3;
        bool found2 = false;

        uint8_t s1[] = { 0x84, 0xC0, 0x0F, 0x84 };
        std::vector<uint8_t> pat1(s1, s1 + sizeof(s1));
        size_t b1 = find_pattern(data, pat1, from);
        if (b1 != SIZE_MAX) {
            size_t jz_off = b1 + 2;
            std::cout << " Patch 2 - HMAC check (JZ near)\n"
                << "     Found at 0x" << std::hex << b1 << "\n"
                << "     Bytes: " << hex_bytes(data.data() + jz_off, 6) << "\n";
            if (data[jz_off] == 0x0F && data[jz_off + 1] == 0x84) {
                for (int i = 0; i < 6; i++) data[jz_off + i] = 0x90;
                std::cout << "     NOPed 6 bytes\n\n";
                ok++;
                found2 = true;
            }
        }

        if (!found2) {
            uint8_t s2[] = { 0x84, 0xC0, 0x74 };
            std::vector<uint8_t> pat2(s2, s2 + sizeof(s2));
            size_t b2 = find_pattern(data, pat2, from);
            if (b2 != SIZE_MAX) {
                size_t jz_off = b2 + 2;
                std::cout << " Patch 2 - HMAC check (JZ short)\n"
                    << "     Found at 0x" << std::hex << b2 << "\n";
                if (data[jz_off] == 0x74) {
                    data[jz_off] = 0xEB;
                    std::cout << "     74 >>> EB\n\n";
                    ok++;
                    found2 = true;
                }
            }
        }

        if (!found2)
            std::cout << " Patch 2: not found skipping\n\n";
    }

    // PATCH 3 - CheckInit: cmp rax,3 + JNZ -> NOP NOP
    {
        bool found3 = false;

        uint8_t s3a[] = { 0x48, 0x83, 0xF8, 0x03, 0x75 };
        std::vector<uint8_t> pat3a(s3a, s3a + sizeof(s3a));
        size_t b3 = find_pattern(data, pat3a);
        if (b3 != SIZE_MAX) {
            size_t off = b3 + 4;
            std::cout << "Patch 3 - CheckInit (cmp rax,3)\n"
                << "     Found at 0x" << std::hex << b3 << "\n";
            if (data[off] == 0x75) {
                data[off] = 0x90;
                data[off + 1] = 0x90;
                std::cout << "    [+] 75 xx -> 90 90\n\n";
                ok++;
                found3 = true;
            }
        }

        if (!found3) {
            uint8_t s3b[] = { 0x48, 0x83, 0xFB, 0x03, 0x75 };
            std::vector<uint8_t> pat3b(s3b, s3b + sizeof(s3b));
            size_t b3b = find_pattern(data, pat3b);
            if (b3b != SIZE_MAX) {
                size_t off = b3b + 4;
                if (data[off] == 0x75) {
                    data[off] = 0x90;
                    data[off + 1] = 0x90;
                    std::cout << "Patch 3b - CheckInit (cmp rbx,3) patched\n\n";
                    ok++;
                    found3 = true;
                }
            }
        }

        if (!found3)
            std::cout << "Patch 3: not found skipping\n\n";
    }

    // PATCH 4 - Replace about-screen strings with cracker tag
    std::cout << "Patch 4 - Replace strings\n";
    {
        // Main tag in the longest slot
        patch_string(data,
            "All participants slot",
            "All participants: wh1tness, Qustsu, OwnCypres35",
            "cracked by https://t.me/+5EHmo7zE-KBlYzMy");
        ok++;

        // Blank out the other slots (replace with spaces to same length)
        // "Author/Coder: wh1tness" = 22 chars >>> 22 spaces
        patch_string(data,
            "Author/Coder slot",
            "Author/Coder: wh1tness",
            "                      ");

        // "Designer: wh1tness/Qustsu" = 25 >>> 25 spaces
        patch_string(data,
            "Designer slot",
            "Designer: wh1tness/Qustsu",
            "                         ");

        // "Helped:  OwnCypres35" = 20 >>> 20 spaces
        patch_string(data,
            "Helped slot",
            "Helped:  OwnCypres35",
            "                    ");

        // "Sponsor: Imperium" = 17 >>> 17 spaces
        patch_string(data,
            "Sponsor slot",
            "Sponsor: Imperium",
            "                 ");

        // "https://discord.gg/jjaRTswhYW" = 29 >>> 29 spaces
        patch_string(data,
            "Discord link slot",
            "https://discord.gg/jjaRTswhYW",
            "                             ");
    }
    std::cout << "\n";

    std::cout << "Code patches applied : " << std::dec << ok << " / 3\n";

    size_t dot = path.rfind('.');
    std::string out = (dot != std::string::npos)
        ? path.substr(0, dot) + "_cracked.exe"
        : path + "_cracked.exe";

    std::ofstream fout(out, std::ios::binary);
    if (!fout) { std::cerr << "Can't write: " << out << "\n"; return 1; }
    fout.write(reinterpret_cast<char*>(data.data()), data.size());
    fout.close();
    std::cout << "Saved :\n    " << out << "\n";
    return 0;
}

int main() {
    int ret = run();
    std::cout << "\nPress any key to exit";
    std::cin.get();
    return ret;
}