#include <Windows.h>

#define WORKER_FACTORY_RELEASE_WORKER 0x0001
#define WORKER_FACTORY_WAIT 0x0002
#define WORKER_FACTORY_SET_INFORMATION 0x0004
#define WORKER_FACTORY_QUERY_INFORMATION 0x0008
#define WORKER_FACTORY_READY_WORKER 0x0010
#define WORKER_FACTORY_SHUTDOWN 0x0020

#define WORKER_FACTORY_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | WORKER_FACTORY_RELEASE_WORKER | WORKER_FACTORY_WAIT | WORKER_FACTORY_SET_INFORMATION | WORKER_FACTORY_QUERY_INFORMATION | WORKER_FACTORY_READY_WORKER | WORKER_FACTORY_SHUTDOWN)

BOOL InjectViaJobCallback(HANDLE targetProcess, PVOID payloadAddress, HANDLE hIoPort);
BOOL InjectViaTpWait(HANDLE targetProcess, PVOID payloadAddress, HANDLE hIoPort);
BOOL InjectViaTpIo(HANDLE targetProcess, PVOID payloadAddress, HANDLE hIoPort);
BOOL InjectViaAlpc(HANDLE targetProcess, PVOID payloadAddress, HANDLE hIoPort);
BOOL InjectViaTpDirect(HANDLE targetProcess, PVOID payloadAddress, HANDLE hIoPort);

BOOL InjectViaTpTimer(HANDLE hWorkerFactory, HANDLE hTimer, PVOID payloadAddress, HANDLE targetProcess);

BOOL InjectViaWorkerFactoryStartRoutine(HANDLE targetProcess, HANDLE hWorkerFactory, PVOID localPayloadAddress, size_t payloadSize);
BOOL InjectViaTpWork(HANDLE targetProcess, PVOID payloadAddress, HANDLE hWorkerFactory);
