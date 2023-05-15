/*
	Author      =>  Abdallah Mohamed
	Date        =>  14-5-2023/10:13PM
	Greetz to   =>  Hossam Ehab
*/

#include <Windows.h>
#include <stdio.h>


#define DEREF(x)*(DWORD_PTR *)(x)

typedef enum UNHOOK_STATUS { UNHOOK_SUCCESS, NO_HOOKS, NO_IMPORTS, INVALID_PE, UNHOOK_FAIL } UNHOOK_STATUS;

extern LPVOID GetImgBaseAddr();


UNHOOK_STATUS UnhookIAT(LPVOID lpImgBaseAddr)
{
	PIMAGE_NT_HEADERS pNtHdr = (PIMAGE_NT_HEADERS)( (DWORD_PTR)lpImgBaseAddr + ( (PIMAGE_DOS_HEADER)lpImgBaseAddr )->e_lfanew );
	PIMAGE_DATA_DIRECTORY pImportDir = (PIMAGE_DATA_DIRECTORY)&pNtHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	PIMAGE_IMPORT_DESCRIPTOR pDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD_PTR)lpImgBaseAddr + pImportDir->VirtualAddress);
	BOOL bNoHooks = TRUE;

	if (( (PIMAGE_DOS_HEADER)lpImgBaseAddr )->e_magic != IMAGE_DOS_SIGNATURE || pNtHdr->Signature != IMAGE_NT_SIGNATURE) return INVALID_PE;
	if (( pImportDir->Size / sizeof(IMAGE_IMPORT_DESCRIPTOR) ) == 0) return NO_IMPORTS;

	do {
		PIMAGE_THUNK_DATA pILT = (PIMAGE_THUNK_DATA)((DWORD_PTR)lpImgBaseAddr + pDescriptor->OriginalFirstThunk);
		DWORD_PTR dwpIAT = (DWORD_PTR)lpImgBaseAddr + pDescriptor->FirstThunk;

		while ( DEREF(dwpIAT) )
		{
			PIMAGE_IMPORT_BY_NAME pLookup = (PIMAGE_IMPORT_BY_NAME)((DWORD_PTR)lpImgBaseAddr + pILT->u1.AddressOfData);
			DWORD_PTR pTrueAddr = (DWORD_PTR)GetProcAddress(
				GetModuleHandleA((LPCSTR)((DWORD_PTR)lpImgBaseAddr + pDescriptor->Name)),
				pLookup->Name
			);

			if ( DEREF(dwpIAT) != pTrueAddr )
			{
				bNoHooks = FALSE;
				printf("[-] Function Name %s in %s DLL is Hooked, its address is 0x%p, the true address is 0x%p\n", pLookup->Name, (LPCSTR)((DWORD_PTR)lpImgBaseAddr + pDescriptor->Name), (PVOID)DEREF(dwpIAT), (PVOID)pTrueAddr);

				/* Unhook it */
				DWORD dwOldProtect = 0;
				if (!VirtualProtect((LPVOID)dwpIAT, sizeof(DWORD_PTR), PAGE_READWRITE, &dwOldProtect)) return UNHOOK_FAIL;
				DEREF(dwpIAT) = pTrueAddr;
				if (!VirtualProtect((LPVOID)dwpIAT, sizeof(DWORD_PTR), dwOldProtect, &dwOldProtect)) return UNHOOK_FAIL;
			}


			dwpIAT += sizeof(DWORD_PTR);
			pILT++;
		}

		pDescriptor++;

	} while ( pDescriptor->Name );

	return ( bNoHooks ? NO_HOOKS : UNHOOK_SUCCESS );
}


int main(int argc, char **argv)
{

	switch (
		UnhookIAT(
			/*
			// We have several ways to get our image base address

			// The easiest way
			(LPVOID)GetModuleHandleA(NULL)

			// Also we can get it from PEB

			// But we use another technique developed in assembly
			*/
			GetImgBaseAddr()
		)
		)
	{
	case UNHOOK_SUCCESS:
		puts("Import Address Table Unhooked Successfully");
		break;

	case NO_HOOKS:
		puts("Import Address Table is clean, there is no hooks");
		break;

	case NO_IMPORTS:
		puts("There is no imports to unhook");
		break;

	case INVALID_PE:
		puts("The given PE isn't valid");
		break;

	case UNHOOK_FAIL:
		puts("Failed to unhook IAT");
		break;

	default:
		break;
	}


	return EXIT_SUCCESS;
}
