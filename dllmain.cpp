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

typedef int(WINAPI* TrueMessageBox)(HWND, LPCTSTR, LPCTSTR, UINT);

TrueMessageBox trueMessageBox = MessageBoxW;

BOOL WINAPI MessageBoxHook(HWND hWnd, LPCTSTR lpText, LPCTSTR lpCaption, UINT uType)
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

// Find the correct function in the Export Name Pointer Table
DWORD get_name_pointer_table_index(UINT_PTR base, PIMAGE_EXPORT_DIRECTORY export_directory, const char* function_name)
{
	// Get addresses of the arrays
	PDWORD name_offset_array = reinterpret_cast<PDWORD>(base + export_directory->AddressOfNames);

	// Cycle through all pointers in the Export Name Pointer Table 
	// (contains pointers to the ASCII names of the functions)
	for (DWORD i = 0; i < export_directory->NumberOfFunctions; ++i)
	{
		// Follow the pointer to the ASCII names of the functions in the Export Name Table
		const char* current_name = reinterpret_cast<const char*>(base + name_offset_array[i]);
		
		if (_stricmp(function_name, current_name) == 0) {
			fprintf(console.stream, "Found module %s in Export Name Table at index %d\n", function_name, i);
			return i;
		}
	}

	return -1;
}

// Use the index in the Export Ordinal Table (forms a parallel array with the Export Name Pointer Table
// Add the Export Address Table RVA to find the address of the exported function
PDWORD get_export_offset_address(UINT_PTR base, PIMAGE_EXPORT_DIRECTORY export_directory, DWORD index)
{
	PWORD ordinal_array = reinterpret_cast<PWORD>(base + export_directory->AddressOfNameOrdinals); //word because ordinal table has 16 bit entries
	
	PWORD ordinal_base = reinterpret_cast<PWORD>(base + export_directory->Base);

	//biased ordinal? => have to subtract ordinal base?
	WORD indexEAT = ordinal_array[index] - *ordinal_base; 

	PDWORD function_offset_array = reinterpret_cast<PDWORD>(base + export_directory->AddressOfFunctions);

	// We want to get the address of the DWORD, so we use pointer arithmetics instead of function_offset_array[current_ordinal]
	PDWORD current_function_offset = function_offset_array + indexEAT;

	// Note: the Export Address Table can also contain a forwarder, 
	// in this case the address will point to outside the current module

	return current_function_offset;
}

// Install the hook (overwrite the pointer in the Export Address Table)
void overwriteEAT(UINT_PTR base, PDWORD offset, DWORD pointer) {
	// Change the protection so we can overwrite the pointer, store the old protection
	DWORD old_protection{};
	VirtualProtect(offset, sizeof(UINT_PTR), PAGE_READWRITE, &old_protection);

	// Overwrite the address with a pointer to another function
	*offset = pointer;

	// Restore the old protection
	VirtualProtect(offset, sizeof(UINT_PTR), old_protection, &old_protection);
}

// Storing these values to be able to use them in the attach and detach
HMODULE h_module = NULL;
UINT_PTR base = 0; //Using UINT_PTR because it scales to the size of a pointer for both 32-bit and 64-bit Windows 
PDWORD offset_address = nullptr;

// Testing the hook by retrieving the address of the function with GetProcAddress
void test_hook() {
	FARPROC address = GetProcAddress(h_module, function_name);
	fprintf(console.stream, "Hook function is located at address %p\n", &MessageBoxHook);
	fprintf(console.stream, "GetProcAddress found address %p for function %s\n", address, function_name);

	if (address != nullptr) {
		// Use the address to open a messagebox
		// If the hook is active, the text will be changed
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

		PIMAGE_EXPORT_DIRECTORY p_export_dir = get_export_directory(base);
		fprintf(console.stream, "Found address %p for Export Directory Table of module %s\n", p_export_dir, module_name);

		DWORD index = get_name_pointer_table_index(base, p_export_dir, function_name);
		if (index == -1) {
			fprintf(console.stream, "Unable to find function %s in Export Name Pointer Table\n", function_name);
			return TRUE;
		}
		fprintf(console.stream, "Found function %s at index %d in Export Name Pointer Table\n", function_name, index);



		offset_address = get_export_offset_address(base, p_export_dir, index);
		fprintf(console.stream, "Found address %d of exported function %s in the Export Address Table\n", base+*offset_address, function_name);// EAT contains an offset from the base
		fprintf(console.stream, "True function is located at address %p\n", trueMessageBox);		

		DWORD hook_offset = (DWORD)&MessageBoxHook - base;
		overwriteEAT(base, offset_address, hook_offset);
		fprintf(console.stream, "Overwrote the pointer in the Export Address Table with the pointer to our original function %d\n", hook_offset);

		// todo: test that install was successfull by using GetProcAddress
		FARPROC address = GetProcAddress(h_module, function_name);
		
		test_hook();

		return TRUE;
	}
						   

	case DLL_THREAD_ATTACH: break;
	case DLL_THREAD_DETACH: break;
	case DLL_PROCESS_DETACH: {
		// overwrite the address with the original address (unhook)
		overwriteEAT(base, offset_address, (DWORD)trueMessageBox-base); 
		test_hook();
		
		return TRUE;
	}

	}
}
