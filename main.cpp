#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <regex>
#include <string>
HANDLE hHandle;

// Templates //
template<typename T> T RPM(SIZE_T address) {
	T buffer; ReadProcessMemory(hHandle, (void*)address, &buffer, sizeof(T), nullptr);
	return buffer;
}

// Functions //
auto get_module(const char* cModuleName, DWORD dProcId) {
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, dProcId);
	if (hSnapshot != INVALID_HANDLE_VALUE) {
		MODULEENTRY32 modEntry;
		modEntry.dwSize = sizeof(modEntry);
		if (Module32First(hSnapshot, &modEntry)) {
			do {
				if (!strcmp(modEntry.szModule, cModuleName)) {
					CloseHandle(hSnapshot);
					return modEntry;
				}
			} while (Module32Next(hSnapshot, &modEntry));
		}
	}
	return MODULEENTRY32();
}
auto str_replace_all(std::string& subject, const std::string& search, const std::string& replace) -> void{
	size_t pos = 0;
	while ((pos = subject.find(search, pos)) != std::string::npos) {
		subject.replace(pos, search.length(), replace);
		pos += replace.length();
	}
}
auto find_pattern(const MODULEENTRY32& module, const std::string& str, std::string ida, int offset, int extra, bool relative = true) -> uintptr_t {
	ida.insert(0, " ");
	std::transform(ida.begin(), ida.end(), ida.begin(), tolower);
	str_replace_all(ida, " ??", " ?");
	str_replace_all(ida, " ?", " ??");
	str_replace_all(ida, " ", "");

	std::string pattern;

	for (unsigned int i = 0; i < ida.size(); i += 2) {
		std::string word = ida.substr(i, 2);
		if (word == "??") pattern += ".";
		else pattern += (char)strtol(word.c_str(), NULL, 16);
	}

	uintptr_t address;
	std::smatch sm;
	std::regex_search(str, sm, std::regex(pattern));

	if (sm.size() == 0) return 0x0;
	else address = sm.position(0);

	address += (uintptr_t)module.modBaseAddr + offset;
	address = RPM<uint32_t>(address) + extra;
	return relative ? address - (uintptr_t)module.modBaseAddr : address;
}


// EntryPoint //
int main(int argc, char** argv) {
	HWND hwnd = FindWindow(0, "RainbowSix");
	DWORD dProcId; GetWindowThreadProcessId(hwnd, &dProcId);
	hHandle = OpenProcess(PROCESS_VM_READ, false, dProcId);
	
	auto client = get_module("RainbowSix.exe", dProcId);
	std::string bytes(client.modBaseSize, ' ');
	ReadProcessMemory(hHandle, (void*)client.modBaseAddr, (void*)bytes.data(), client.modBaseSize, nullptr);
	
	printf("pGameFramework: 0x%X\n", find_pattern(client, bytes, "48 8B 0D ? ? ? ? 48 8B 01 FF 90 ? ? ? ? 48 8B 54 24 ? 4C 8D 0D ? ? ? ? ", 0x1, 0x1));
	printf("pRender: 0x%X\n", find_pattern(client, bytes, "48 83 3D ? ? ? ? ? 0F 84 ? ? ? ? 48 89 B4 24 ? ? ? ?", 0x1, 0x1));
	bytes.~basic_string();
	
	return 0;
}
