//      EAT Redirection - The EAT, or Export Address Table is similar to the
//		IAT.  Except in the opposite direction.  When a module exports a function 
//		so that it can be used by other modules, it stores the address of  
//		that function in it's EAT.  EAT redirection overwrites that address 
//		with the offset of your hook.  EAT redirection will not affect any 
//		currently loaded modules.  It will only affect modules loaded after the 
//		redirection	has been made.  It will also affect subsequent calls to 
//		GetProcAddress(), as they will return the address of your hook instead of 
//		the real function. 

#include <iostream>
#include <Windows.h>
#include <winternl.h>
#include "Console.h"

Console console;

/*--------------------------------------------------
		User32.dll MessageBox hook
----------------------------------------------------*/
typedef int(WINAPI* TrueMessageBox)(HWND, LPCTSTR, LPCTSTR, UINT);

TrueMessageBox trueMessageBox = NULL;

BOOL WINAPI MessageBoxHook(HWND hWnd, LPCTSTR lpText, LPCTSTR lpCaption, UINT uType)
{
	LPCTSTR lpCaptionChanged = L"Hooked MessageBox";
	return trueMessageBox(hWnd, lpText, lpCaptionChanged, uType);
}

#include <fstream>
PDWORD get_export_offset_address(uintptr_t module_base_address, const char* function_name)
{

	// Parse PE header
	PIMAGE_DOS_HEADER dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(module_base_address);
	PIMAGE_NT_HEADERS ntHeader = reinterpret_cast<PIMAGE_NT_HEADERS>(module_base_address + dosHeader->e_lfanew);
	IMAGE_DATA_DIRECTORY export_datadir = ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	PIMAGE_EXPORT_DIRECTORY export_directory = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(module_base_address + export_datadir.VirtualAddress);

	// Get addresses of the arrays
	PDWORD name_offset_array = reinterpret_cast<PDWORD>(module_base_address + export_directory->AddressOfNames);
	PWORD ordinal_array = reinterpret_cast<PWORD>(module_base_address + export_directory->AddressOfNameOrdinals); //word because ordinal table has 16 bit entries
	PDWORD function_offset_array = reinterpret_cast<PDWORD>(module_base_address + export_directory->AddressOfFunctions);

	// Cycle through all function pointers
	for (int i=0; i < export_directory->NumberOfFunctions; ++i)
	{
		const char* current_name = reinterpret_cast<const char*>(module_base_address + name_offset_array[i]);

		fprintf(console.stream, "%s \n", current_name);

		if (_stricmp(function_name, current_name))
			continue;

		PWORD ordinal_base = reinterpret_cast<PWORD>(module_base_address + export_directory->Base);
		WORD indexEAT = ordinal_array[i] - *ordinal_base; //biased ordinal? => have to subtract ordinal base?

		fprintf(console.stream, "%d \n", indexEAT);
		fprintf(console.stream, "%d \n", *ordinal_base);

		// We want to get the address of the DWORD, so we use pointer arithmetics instead of function_offset_array[current_ordinal]
		PDWORD current_function_offset = function_offset_array + indexEAT;

		return current_function_offset;
	}

	return nullptr;
}


DWORD WINAPI installEATHook(PVOID base) {

	TrueMessageBox hookedMessageBox1 = reinterpret_cast<TrueMessageBox>(GetProcAddress(GetModuleHandle(L"user32.dll"), "MessageBoxW"));
	hookedMessageBox1(NULL, L"before hook with GetProcAddress", L"box with getProcAddress", MB_OK);
	
	uintptr_t module_base_address = (uintptr_t)GetModuleHandle(L"user32.dll");
	PDWORD messageBoxW_offset_address = get_export_offset_address(module_base_address, "MessageBoxW");

	if (messageBoxW_offset_address == nullptr) {
		return FALSE;
	}

	DWORD hook_offset = (uintptr_t)&MessageBoxHook - module_base_address;

	DWORD old_protection{};
	VirtualProtect(messageBoxW_offset_address, sizeof(DWORD), PAGE_READWRITE, &old_protection);
	*messageBoxW_offset_address = hook_offset;
	VirtualProtect(messageBoxW_offset_address, sizeof(DWORD), old_protection, &old_protection);

	// open messagebox for test
	TrueMessageBox hookedMessageBox2 = reinterpret_cast<TrueMessageBox>(GetProcAddress(GetModuleHandle(L"user32.dll"), "MessageBoxW"));
	hookedMessageBox2(NULL, L"after hook with GetProcAddress", L"box with getProcAddress", MB_OK);

	//Loadlibrary again to affect program that doesnt use GetProcAddress?

	return TRUE;
}

BOOL APIENTRY DllMain( HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
	case DLL_PROCESS_ATTACH: {
		if (!console.open()) {
			// Indicate DLL loading failed
			return FALSE;
		}
		CreateThread(nullptr, NULL, installEATHook, hModule, NULL, nullptr); break;
	}
        
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
