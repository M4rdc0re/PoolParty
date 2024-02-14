#pragma once
#include <Windows.h>
#include "structs.h"

typedef NTSTATUS(NTAPI* fnNtQueryInformationProcess)(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
);

typedef NTSTATUS(NTAPI* fnTpAllocJobNotification)(
    PFULL_TP_JOB* JobReturn,
    HANDLE HJob,
    PVOID Callback,
    PVOID Context,
    PTP_CALLBACK_ENVIRON CallbackEnviron
 );

typedef NTSTATUS(NTAPI* fnNtQueryObject)(
    HANDLE Handle,
    OBJECT_INFORMATION_CLASS ObjectInformationClass,
    PVOID ObjectInformation,
    ULONG ObjectInformationLength,
    PULONG ReturnLength
);

typedef NTSTATUS(NTAPI* fnRtlAdjustPrivilege)(
    ULONG Privilege,
    BOOLEAN Enable,
    BOOLEAN Client,
    PBOOLEAN WasEnabled
);

typedef NTSTATUS(NTAPI* fnNtQuerySystemInformation)(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID                    SystemInformation,
    ULONG                    SystemInformationLength,
    PULONG                   ReturnLength
);

typedef NTSTATUS(NTAPI* fnNtAssociateWaitCompletionPacket)(
    HANDLE WaitCompletionPacketHandle,
    HANDLE IoCompletionHandle,
    HANDLE TargetObjectHandle,
    PVOID KeyContext,
    PVOID ApcContext,
    NTSTATUS IoStatus,
    ULONG_PTR IoStatusInformation,
    PBOOLEAN AlreadySignaled
);

typedef NTSTATUS(NTAPI* fnNtSetInformationFile)(
    HANDLE FileHandle,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID FileInformation,
    ULONG Length,
    FILE_INFORMATION_CLASS FileInformationClass
);

typedef NTSTATUS(NTAPI* fnNtAlpcCreatePort)(
    HANDLE PortHandle,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PALPC_PORT_ATTRIBUTES PortAttributes
);

typedef NTSTATUS(NTAPI* fnTpAllocAlpcCompletion)(
    PFULL_TP_ALPC* AlpcReturn,
    HANDLE AlpcPort,
    PTP_ALPC_CALLBACK Callback,
    PVOID Context,
    PTP_CALLBACK_ENVIRON CallbackEnviron
);

typedef NTSTATUS(NTAPI* fnRtlInitUnicodeString)(
    PUNICODE_STRING DestinationString,
    PCWSTR SourceString
);

typedef NTSTATUS(NTAPI* fnNtAlpcSetInformation)(
    HANDLE PortHandle,
    ULONG PortInformationClass,
    PVOID PortInformation,
    ULONG Length
);

typedef NTSTATUS(NTAPI* fnNtAlpcConnectPort)(
    PHANDLE PortHandle,
    PUNICODE_STRING PortName,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PALPC_PORT_ATTRIBUTES PortAttributes,
    DWORD ConnectionFlags,
    PSID RequiredServerSid,
    PPORT_MESSAGE ConnectionMessage,
    PSIZE_T ConnectMessageSize,
    PALPC_MESSAGE_ATTRIBUTES OutMessageAttributes,
    PALPC_MESSAGE_ATTRIBUTES InMessageAttributes,
    PLARGE_INTEGER Timeout
);

typedef NTSTATUS(NTAPI* fnNtSetIoCompletion)(
    HANDLE IoCompletionHandle,
    PVOID KeyContext,
    PVOID ApcContext,
    NTSTATUS IoStatus,
    ULONG_PTR IoStatusInformation
);

typedef NTSTATUS(NTAPI* fnNtQueryInformationWorkerFactory)(
    HANDLE WorkerFactoryHandle,
    QUERY_WORKERFACTORYINFOCLASS WorkerFactoryInformationClass,
    PVOID WorkerFactoryInformation,
    ULONG WorkerFactoryInformationLength,
    PULONG ReturnLength
);

typedef NTSTATUS(NTAPI* fnNtSetTimer2)(
    HANDLE TimerHandle,
    PLARGE_INTEGER DueTime,
    PLARGE_INTEGER Period,
    PT2_SET_PARAMETERS Parameters
);

typedef NTSTATUS(NTAPI* fnNtSetInformationWorkerFactory)(
    HANDLE WorkerFactoryHandle,
    SET_WORKERFACTORYINFOCLASS WorkerFactoryInformationClass,
    PVOID WorkerFactoryInformation,
    ULONG WorkerFactoryInformationLength
);