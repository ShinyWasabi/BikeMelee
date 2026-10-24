#include <Windows.h>
#include <cstdint>
#include <string>
#include <vector>
#include <optional>
#include <filesystem>

uintptr_t ScanPattern(uint8_t* base, const std::vector<std::optional<uint8_t>>& pattern)
{
    PIMAGE_DOS_HEADER dos = reinterpret_cast<PIMAGE_DOS_HEADER>(base);
    PIMAGE_NT_HEADERS nt = reinterpret_cast<PIMAGE_NT_HEADERS>(base + dos->e_lfanew);

    size_t moduleSize = nt->OptionalHeader.SizeOfImage;
    size_t patternSize = pattern.size();

    for (size_t i = 0; i < moduleSize - patternSize; i++)
    {
        bool match = true;
        for (size_t j = 0; j < patternSize; j++)
        {
            if (pattern[j].has_value() && base[i + j] != pattern[j].value())
            {
                match = false;
                break;
            }
        }

        if (match)
            return reinterpret_cast<uintptr_t>(base + i);
    }

    return 0;
}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(instance);

        uint8_t* base = reinterpret_cast<uint8_t*>(GetModuleHandleA(0));
        if (!base)
            return FALSE;

        char buf[MAX_PATH];
        GetModuleFileNameA(nullptr, buf, MAX_PATH);
        std::string name = std::filesystem::path(buf).filename().string();

        uintptr_t addr1 = 0;
        uintptr_t addr2 = 0;

        if (name == "GTA5.exe")
        {
            addr1 = ScanPattern(base, { 0x0F, 0x84, std::nullopt, std::nullopt, std::nullopt, std::nullopt, 0x48, 0x8B, 0x91, std::nullopt, std::nullopt, std::nullopt, std::nullopt, 0x8B, 0x82 });
            addr2 = ScanPattern(base, { 0x75, std::nullopt, 0x8B, 0x83, std::nullopt, std::nullopt, std::nullopt, std::nullopt, 0xC1, 0xE8, std::nullopt, 0x41, 0x84, 0xC5, 0x0F, 0x85, std::nullopt, std::nullopt, std::nullopt, std::nullopt, 0x83, 0x7B });

            if (!addr1 || !addr2)
                return FALSE;

            DWORD oldProtect;
            VirtualProtect(reinterpret_cast<void*>(addr1), 6, PAGE_EXECUTE_READWRITE, &oldProtect);
            *reinterpret_cast<uint8_t*>(addr1) = 0x90;
            *reinterpret_cast<uint8_t*>(addr1 + 1) = 0x90;
            *reinterpret_cast<uint8_t*>(addr1 + 2) = 0x90;
            *reinterpret_cast<uint8_t*>(addr1 + 3) = 0x90;
            *reinterpret_cast<uint8_t*>(addr1 + 4) = 0x90;
            *reinterpret_cast<uint8_t*>(addr1 + 5) = 0x90;
            VirtualProtect(reinterpret_cast<void*>(addr1), 6, oldProtect, &oldProtect);

            VirtualProtect(reinterpret_cast<void*>(addr2), 1, PAGE_EXECUTE_READWRITE, &oldProtect);
            *reinterpret_cast<uint8_t*>(addr2) = 0xEB;
            VirtualProtect(reinterpret_cast<void*>(addr2), 1, oldProtect, &oldProtect);
        }
        else if (name == "GTA5_Enhanced.exe")
        {
            addr1 = ScanPattern(base, { 0x74, std::nullopt, 0x48, 0x89, 0xCE, 0x48, 0x8B, 0x81, std::nullopt, std::nullopt, std::nullopt, std::nullopt, 0x31, 0xFF });
            addr2 = ScanPattern(base, { 0x75, std::nullopt, 0xF6, 0x86, std::nullopt, std::nullopt, std::nullopt, std::nullopt, std::nullopt, 0x0F, 0x85, std::nullopt, std::nullopt, std::nullopt, std::nullopt, 0x83, 0x7E });

            if (!addr1 || !addr2)
                return FALSE;

            DWORD oldProtect;
            VirtualProtect(reinterpret_cast<void*>(addr1), 2, PAGE_EXECUTE_READWRITE, &oldProtect);
            *reinterpret_cast<uint8_t*>(addr1) = 0x90;
            *reinterpret_cast<uint8_t*>(addr1 + 1) = 0x90;
            VirtualProtect(reinterpret_cast<void*>(addr1), 2, oldProtect, &oldProtect);

            VirtualProtect(reinterpret_cast<void*>(addr2), 1, PAGE_EXECUTE_READWRITE, &oldProtect);
            *reinterpret_cast<uint8_t*>(addr2) = 0xEB;
            VirtualProtect(reinterpret_cast<void*>(addr2), 1, oldProtect, &oldProtect);
        }
    }

    return TRUE;
}