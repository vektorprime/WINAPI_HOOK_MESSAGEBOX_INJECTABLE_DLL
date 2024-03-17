//This is a working and injectable DLL. 

#include "pch.h"
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

/// Define the prototype for MessageBoxW function pointer
typedef int(WINAPI *PrototypeMessageBox)(HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption, UINT uType);

// Pointer to the original MessageBoxW function
PrototypeMessageBox originalMessageBoxW = MessageBoxW;

// Hooked MessageBoxW function
int hookedMessageBoxW(HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption, UINT uType)
{
    // Call the original messagebox with your hooked message. Don't call hookedMessageBoxW because that will cause a recursive loop.
    originalMessageBoxW(NULL, L"Hooked", L"Hooked", 0);

    // Call the original MessageBoxW
    return originalMessageBoxW(hWnd, lpText, lpCaption, uType);
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{
    PrototypeMessageBox pMessageBoxW;
    HMODULE hModule = 0;
    DWORD oldProtect = 0;

    PIMAGE_DOS_HEADER pDosHeader;

    // Get the address of the IMAGE_NT_HEADERS
    PIMAGE_NT_HEADERS pNtHeader;

    // Get the address of the IMAGE_IMPORT_DESCRIPTOR
    PIMAGE_IMPORT_DESCRIPTOR pImportDesc;

    switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH:
        // Get the base address of the current module
        hModule = GetModuleHandle(NULL);
        if (hModule == NULL) {
            // Error handling
            return 1;
        }

        // Get the address of the IMAGE_DOS_HEADER
        pDosHeader = (PIMAGE_DOS_HEADER)hModule;

        // Get the address of the IMAGE_NT_HEADERS
        pNtHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)hModule + pDosHeader->e_lfanew);

        // Get the address of the IMAGE_IMPORT_DESCRIPTOR
        pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD_PTR)hModule + pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

        // Iterate over each imported module
        while (pImportDesc->Name != NULL)
        {
            // Get the name of the imported module
            LPCSTR szModuleName = (LPCSTR)((DWORD_PTR)hModule + pImportDesc->Name);

            // Check if the imported module is kernel32.dll (just as an example)
            if (strcmp(szModuleName, "USER32.dll") == 0)
            {
                // Get the address of the thunk array
                PIMAGE_THUNK_DATA pThunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)hModule + pImportDesc->FirstThunk);

                // Iterate over each function in the import address table (IAT)
                while (pThunk->u1.Function != NULL)
                {
                    // Check if the function is MessageBoxW
                    if ((DWORD_PTR)pThunk->u1.Function == (DWORD_PTR)originalMessageBoxW)
                    {
                        // Modify the memory protection of the page
                        DWORD dwOldProtect;
                        if (!VirtualProtect(&pThunk->u1.Function, sizeof(DWORD_PTR), PAGE_READWRITE, &dwOldProtect))
                        {
                            // Error handling
                            return 1;
                        }

                        // Hook the function by replacing its address with the address of our hooked function
                        pThunk->u1.Function = (DWORD_PTR)hookedMessageBoxW;

                        // Restore the original memory protection
                        VirtualProtect(&pThunk->u1.Function, sizeof(DWORD_PTR), dwOldProtect, &dwOldProtect);
                    }

                    // Move to the next thunk
                    ++pThunk;
                }
            }

            // Move to the next imported module
            ++pImportDesc;
        }

        break;
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
