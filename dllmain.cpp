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
LPCSTR module_name = "user32.dll";
LPCSTR function_name = "MessageBoxW";

typedef int(WINAPI* TrueMessageBox)(HWND, LPCWSTR, LPCWSTR, UINT);

TrueMessageBox trueMessageBox = MessageBoxW;

BOOL WINAPI MessageBoxHook(HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption, UINT uType)
{
	LPCTSTR lpCaptionChanged = L"Hooked MessageBox";
	return trueMessageBox(hWnd, lpText, lpCaptionChanged, uType);
}

// Parse the PE header to find the address of the Export Directory Table
PIMAGE_EXPORT_DIRECTORY get_export_directory(UINT_PTR base)
{	
	PIMAGE_DOS_HEADER dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(base);
	PIMAGE_NT_HEADERS ntHeader = reinterpret_cast<PIMAGE_NT_HEADERS>(base + dosHeader->e_lfanew);
	IMAGE_DATA_DIRECTORY export_datadir = ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	PIMAGE_EXPORT_DIRECTORY export_directory = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(base + export_datadir.VirtualAddress);

	return export_directory;
}

// the Export Name Pointer Table contains pointers to ASCII strings in the Export Name Table 
// that contains the names of all functions that are exported by the module
// - we iterate all pointers and compare the names until we find the correct function
// - we then return the index of that function
DWORD get_function_index(UINT_PTR base, PIMAGE_EXPORT_DIRECTORY export_directory, const char* function_name)
{
	// Get a pointer to the start of the Export Name Pointer Table
	// Note: the pointers are relative to the module base address
	PDWORD export_name_pointer_table = reinterpret_cast<PDWORD>(base + export_directory->AddressOfNames);

	// Cycle through all pointers in the Export Name Pointer Table 
	// (contains pointers to the ASCII names of the functions)
	for (DWORD i = 0; i < export_directory->NumberOfFunctions; ++i)
	{
		// Follow the pointer to the ASCII names of the functions in the Export Name Table
		const char* current_name = reinterpret_cast<const char*>(base + export_name_pointer_table[i]);
		
		if (_stricmp(function_name, current_name) == 0) {
			fprintf(console.stream, "Found %s in Export Name Table at index %d\n", function_name, i);
			return i;
		}
	}

	fprintf(console.stream, "Unable to find %s in Export Name Table\n", function_name);
	return -1;
}

// Install the hook (overwrite the pointer in the Export Address Table)
void overwriteEAT(PDWORD hook_address, DWORD function_address) {
	// Change the protection so we can overwrite the pointer, store the old protection
	DWORD old_protection{};
	VirtualProtect(hook_address, sizeof(DWORD), PAGE_READWRITE, &old_protection);

	// Overwrite the address with a pointer to another function
	*hook_address = function_address;

	// Restore the old protection
	VirtualProtect(hook_address, sizeof(DWORD), old_protection, &old_protection);
}

// Storing these values to be able to use them in the attach and detach
HMODULE h_module = NULL;
UINT_PTR base = 0; //Using UINT_PTR because it scales to the size of a pointer for both 32-bit and 64-bit Windows 
PDWORD hook_address = nullptr; // The entries in the Export Address Table are 4 bytes long

// Testing the hook by retrieving the address of the function with GetProcAddress
void test_hook() {
	fprintf(console.stream, "\nTesting hook using GetProcAddress():\n");

	FARPROC address = GetProcAddress(h_module, function_name);
	fprintf(console.stream, "Using GetProcAddress: %p\n", address);
	
	fprintf(console.stream, "Address hook function: %p\n", &MessageBoxHook);

	// Using the address retrieved by GetProcAddress to create a MessageBox
	// (If the hook is active, the text will be changed)
	if (address != nullptr) {
		TrueMessageBox messageBox = reinterpret_cast<TrueMessageBox>(address);
		messageBox(NULL, L"Regular text", L"Regular caption", MB_OK);
	}
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

		// module handle == base address of the module
		h_module = GetModuleHandleA(module_name);
		if (h_module == NULL) {
			fprintf(console.stream, "Unable to get handle for module %s \n", module_name);
			return TRUE;
		}
		fprintf(console.stream, "Found handle %p for module %s \n", h_module, module_name);

		// module handle == base address of the module
		// but we need to cast it to do correct pointer arithmetic
		base = (UINT_PTR)h_module;
		fprintf(console.stream, "Base address of module: %p\n", base);

		PIMAGE_EXPORT_DIRECTORY p_export_dir = get_export_directory(base);
		fprintf(console.stream, "Address of Export Directory Table: %p\n", p_export_dir);

		// In this example, we identify the function we want to hook by the function name (not by an ordinal)
		// => we first have to use the following tables to obtain the ordinal of the function
		// - the Export Name Pointer Table
		// - the Export Name Table 
		// - the Export Ordinal Table

		// Iterate the Export Name Pointer Table and return the index when we find the function name
		DWORD index = get_function_index(base, p_export_dir, function_name);
		if (index == -1) {
			return TRUE;
		}

		// The Export Name Pointer Table and the Export Ordinal Table are parallel arrays
		// Note: the export ordinal table entries are 2 bytes long!
		PWORD export_ordinal_table = reinterpret_cast<PWORD>(base + p_export_dir->AddressOfNameOrdinals);
		WORD biased_ordinal = export_ordinal_table[index];
		fprintf(console.stream, "Biased ordinal: %d\n", biased_ordinal);

		// Ordinals are biased by the Ordinal Base field of the export directory table. 
		// In other words, the ordinal base must be subtracted from the ordinals to obtain true indexes into the export address table
		// Note: if we wanted to hook a function identified by an ordinal, we could do this step immediately
		DWORD ordinal_base = *reinterpret_cast<PDWORD>(base + p_export_dir->Base);
		DWORD unbiased_ordinal = biased_ordinal - ordinal_base;
		fprintf(console.stream, "Ordinal base: %d\n", ordinal_base);
		fprintf(console.stream, "Unbiased ordinal: %d\n", unbiased_ordinal);
		

		// The unbiased ordinal can be used as an index into the Export Address Table
		// => we overwrite the value we find with the 
		PDWORD export_address_table = reinterpret_cast<PDWORD>(base + p_export_dir->AddressOfFunctions);
		hook_address = export_address_table + unbiased_ordinal;
		fprintf(console.stream, "Hook address: %p\n", hook_address);
		
		// The Export Address Table contains 4 byte offsets to the exported functions
		// the offsets are relative to the base address of the module
		// => we need to calculate the offset to our hook function
		DWORD hook_function_offset = (DWORD)((UINT_PTR)&MessageBoxHook - base);

		// Overwrite the value
		overwriteEAT(hook_address, hook_function_offset);

		// test that install was successfull by using GetProcAddress
		test_hook();

		return TRUE;
	}
						   

	case DLL_THREAD_ATTACH: break;
	case DLL_THREAD_DETACH: break;
	case DLL_PROCESS_DETACH: {
		// overwrite the address with the original address (unhook)
		DWORD true_function_offset = (DWORD)((UINT_PTR)trueMessageBox - base);
		overwriteEAT(hook_address, true_function_offset);
		test_hook();
		
		return TRUE;
	}

	}
}
