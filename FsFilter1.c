
//#include <ntddk.h>
#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>
#include <stdlib.h>
#include <wchar.h>
#include <ntifs.h>
#include <wdm.h>


#pragma comment(lib,"kernel32.lib")

PFLT_PORT port = NULL;
PFLT_PORT ClientPort = NULL;
PFLT_FILTER FilterHandle = NULL;
LONG get_processfileId;
LONG get_processappId;
BOOLEAN gBlockWrite = TRUE;
BOOLEAN gBlockOFF = FALSE;
#define PROCESS_TERMINATE                  (0x0001)

NTSTATUS MiniUnload(FLT_FILTER_UNLOAD_FLAGS Flags);
FLT_PREOP_CALLBACK_STATUS MiniPreCreate(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext);
FLT_PREOP_CALLBACK_STATUS MiniPreWrite(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext);
FLT_PREOP_CALLBACK_STATUS FLTAPI PreOperationCreate(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID* CompletionContext
);



NTSTATUS MiniConnect(PFLT_PORT clientport, PVOID serverportcookie, PVOID Context, ULONG size, PVOID Connectioncookie)
{
	ClientPort = clientport;
	DbgPrint(("connect \r\n"));
	return STATUS_SUCCESS;
}


VOID MiniDisconnect(PVOID connectioncookie)
{
	DbgPrint("disconnect \r\n");
	FltCloseClientPort(FilterHandle, &ClientPort);
}

NTSTATUS MiniSendRec(PVOID portcookie,PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength, PULONG RetLength)
{
	UNICODE_STRING usString;

	PCHAR msg = "hello";
	RtlInitUnicodeString(&usString, NULL); 
	//cap phat bo nho cho chuoi
	usString.Buffer = (PWSTR)ExAllocatePoolWithTag(PagedPool, InputBufferLength, 'MYTL');
	if (usString.Buffer == NULL)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	RtlCopyMemory(usString.Buffer, InputBuffer, InputBufferLength);
	usString.Length = (USHORT)InputBufferLength;
	usString.MaximumLength = (USHORT)InputBufferLength;
	//DbgPrint(("user msg is :"));

	//DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, " %wZ \r\n", &usString);
	//DbgPrint("\n");

	if (usString.Buffer[0] == '$')
	{
		DbgPrint("on block file");
		DbgPrint("\n");
		gBlockWrite = TRUE;
		_ultoa_s(get_processfileId, OutputBuffer, 20, 10);
	}
	if (usString.Buffer[0] == '%')
	{
		DbgPrint(" off block file");
		//DbgPrint("off block file");
		DbgPrint("\n");
		gBlockWrite = FALSE;
		_ultoa_s(get_processfileId, OutputBuffer, 20, 10);
	}
	

	if (usString.Buffer[0] == '^')
	{
		DbgPrint("on block app");
		DbgPrint("\n");
		gBlockOFF = TRUE;
		//_ultoa_s(get_processappId, OutputBuffer, 20, 10);

	}
	if (usString.Buffer[0] == '&')
	{
		DbgPrint("off block app");
		DbgPrint("\n");
		gBlockOFF = FALSE;
		//_ultoa_s(get_processappId, OutputBuffer, 20, 10);

	}

	if (usString.Buffer[0] == '*')
	{
		_ultoa_s(get_processappId, OutputBuffer, 20, 10);

	}
    // get_processId = (LONG)(ULONG_PTR)PsGetCurrentProcessId();

	return STATUS_SUCCESS;
}



const FLT_OPERATION_REGISTRATION Callbacks[] = {
	{IRP_MJ_CREATE,0,PreOperationCreate,NULL},
	{IRP_MJ_WRITE,0,MiniPreWrite,NULL},
	{IRP_MJ_OPERATION_END}
};
const FLT_REGISTRATION FilterRegistration = {
	sizeof(FLT_REGISTRATION),
	FLT_REGISTRATION_VERSION,
	0,
	NULL,
	Callbacks,
	MiniUnload,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL
};
NTSTATUS MiniUnload(FLT_FILTER_UNLOAD_FLAGS Flags) {

	return STATUS_SUCCESS;
}

FLT_PREOP_CALLBACK_STATUS FLTAPI PreOperationCreate(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID* CompletionContext
)
{
	//DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, " %wZ \r\n", &Data->Iopb->TargetFileObject->FileName);
	//DbgPrint("%wZ\n", &Data->Iopb->TargetFileObject->FileName);
	//BOOLEAN check = FALSE;
	PFLT_FILE_NAME_INFORMATION FileNameInfo;
	NTSTATUS status;
	WCHAR Name[500] = { 0 };
	status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &FileNameInfo);
	if (NT_SUCCESS(status)) {
		status = FltParseFileNameInformation(FileNameInfo);
		if (NT_SUCCESS(status)) {

			if (FileNameInfo->Name.MaximumLength < 500) {
				RtlCopyMemory(Name, FileNameInfo->Name.Buffer, FileNameInfo->Name.MaximumLength);

				//DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, " %ws \r\n", Name);

				if ((wcsstr(Name, L"Device\\HarddiskVolume2\\1.txt") != NULL) && gBlockWrite) {
					DbgPrint("Write File is blocked: ");
					DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, " %ws \r\n", Name);
					DbgPrint("\n");
					get_processfileId = (LONG)(ULONG_PTR)PsGetCurrentProcessId();
					Data->IoStatus.Status = STATUS_INVALID_PARAMETER;
					Data->IoStatus.Information = 0;
					FltReleaseFileNameInformation(FileNameInfo);
					//check = TRUE;
					return FLT_PREOP_COMPLETE;
				}
			}

		}
		FltReleaseFileNameInformation(FileNameInfo);
	}

	return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_PREOP_CALLBACK_STATUS MiniPreWrite(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext) {
	
	return FLT_PREOP_SUCCESS_NO_CALLBACK;
}


VOID ProcessNotifyRoutineEx(_Inout_ PEPROCESS Process, _In_ HANDLE ProcessId, _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo)
{
	PUNICODE_STRING string;
	//NTSTATUS status;
	//DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, " %wZ \r\n", CreateInfo->ImageFileName);
	//RtlCopyMemory(Name, CreateInfo->ImageFileName->Buffer, CreateInfo->ImageFileName->MaximumLength);
	SeLocateProcessImageName(Process, &string);
	if ((CreateInfo != NULL))
	{		
		//DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, " %wZ \r\n", string);
		if ((wcsstr(string->Buffer, L"Bai3_GUI.exe") != NULL))
		{
			DbgPrint("hello app is create");
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, " %wZ \r\n", string);
			DbgPrint("\n");
		}
	}	
}
OB_PREOP_CALLBACK_STATUS
PreOperationCallback(
	_In_ PVOID RegistrationContext,
	_Inout_ POB_PRE_OPERATION_INFORMATION PreInfo);

NTKERNELAPI
UCHAR*
PsGetProcessImageFileName(
	__in PEPROCESS Process
);

OB_OPERATION_REGISTRATION obOperationRegistrations[2] = { {0}, {0} };
OB_CALLBACK_REGISTRATION obCallbackRegistration = { 0 };
UNICODE_STRING altitude = { 0 };
PVOID RegistrationHandle = NULL;


NTSTATUS
InitObRegistration()
{

	obOperationRegistrations[0].ObjectType = PsProcessType;
	obOperationRegistrations[0].Operations |= OB_OPERATION_HANDLE_CREATE;
	obOperationRegistrations[0].Operations |= OB_OPERATION_HANDLE_DUPLICATE;
	obOperationRegistrations[0].PreOperation = PreOperationCallback;


	obOperationRegistrations[1].ObjectType = PsThreadType;
	obOperationRegistrations[1].Operations |= OB_OPERATION_HANDLE_CREATE;
	obOperationRegistrations[1].Operations |= OB_OPERATION_HANDLE_DUPLICATE;
	obOperationRegistrations[1].PreOperation = PreOperationCallback;


	RtlInitUnicodeString(&altitude, L"1000");

	obCallbackRegistration.Version = ObGetFilterVersion();
	obCallbackRegistration.OperationRegistrationCount = 2;
	obCallbackRegistration.RegistrationContext = NULL;
	obCallbackRegistration.Altitude = altitude;
	obCallbackRegistration.OperationRegistration = obOperationRegistrations;

	return ObRegisterCallbacks(&obCallbackRegistration, &RegistrationHandle);
}


OB_PREOP_CALLBACK_STATUS
PreOperationCallback(_In_ PVOID RegistrationContext,
	_Inout_ POB_PRE_OPERATION_INFORMATION PreInfo)
{
	UNREFERENCED_PARAMETER(RegistrationContext);

	ACCESS_MASK AccessBitsToClear =  PROCESS_TERMINATE;


	PEPROCESS process = (PEPROCESS)PreInfo->Object;

	if (PreInfo->ObjectType == *PsThreadType)
	{
		process = IoThreadToProcess((PETHREAD)PreInfo->Object);
	}
	else if (PreInfo->ObjectType == *PsProcessType)
	{
		process = (PEPROCESS)PreInfo->Object;
	}
	else
	{

		return OB_PREOP_SUCCESS;
	}


	PUCHAR processName = PsGetProcessImageFileName(process);

	if ((_stricmp((char*)processName, "Bai3_GUI.exe") != 0))
	{
		return OB_PREOP_SUCCESS;
	}


	if ((PreInfo->Operation == OB_OPERATION_HANDLE_CREATE) && gBlockOFF)
	{	
		get_processappId = (LONG)(ULONG_PTR)PsGetCurrentProcessId();
	
		PreInfo->Parameters->CreateHandleInformation.DesiredAccess &= ~AccessBitsToClear;
	}

	if ((PreInfo->Operation == OB_OPERATION_HANDLE_DUPLICATE) && gBlockOFF)
	{
		get_processappId = (LONG)(ULONG_PTR)PsGetCurrentProcessId();
		PreInfo->Parameters->DuplicateHandleInformation.DesiredAccess &= ~AccessBitsToClear;

	}
	
	return OB_PREOP_SUCCESS;
}

VOID
UnInitObRegistration()
{
	if (RegistrationHandle)
	{
		ObUnRegisterCallbacks(RegistrationHandle);
		RegistrationHandle = NULL;
	}
}


VOID UnloadRoutine(IN PDRIVER_OBJECT DriverObject)
{
	DbgPrint(("Unloading Driver \r\n"));
	FltCloseCommunicationPort(port);
	FltUnregisterFilter(FilterHandle);
	PsSetCreateProcessNotifyRoutineEx((PCREATE_PROCESS_NOTIFY_ROUTINE_EX)ProcessNotifyRoutineEx, TRUE);
	UnInitObRegistration();
	//DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Unloaded\n");
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
	UNREFERENCED_PARAMETER(RegistryPath);

	PSECURITY_DESCRIPTOR sd;
	OBJECT_ATTRIBUTES oa = { 0 };
	UNICODE_STRING name;
	RtlInitUnicodeString(&name, L"\\mf");

	NTSTATUS status;
	status = STATUS_SUCCESS;

	status = FltRegisterFilter(DriverObject, &FilterRegistration, &FilterHandle);
	if (!NT_SUCCESS(status)) {
		DbgPrint("Failed to register filter! 0x%08x\n", status);
		return status;
	}
	else {
		DbgPrint("Filter registered!\n");
	}

	status = FltBuildDefaultSecurityDescriptor(&sd, FLT_PORT_ALL_ACCESS);
	if (NT_SUCCESS(status))
	{
		InitializeObjectAttributes(&oa, &name, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, sd);
		status = FltCreateCommunicationPort(FilterHandle, &port, &oa, NULL, MiniConnect, MiniDisconnect, MiniSendRec, 1);
		FltFreeSecurityDescriptor(sd);
		if (NT_SUCCESS(status))
		{
			status = FltStartFiltering(FilterHandle);
			if (!NT_SUCCESS(status))
			{
				FltUnregisterFilter(FilterHandle);
				DbgPrint("Failed to start filter! 0x%08x\n", status);
				FltCloseCommunicationPort(port);
				return status;
			}
			else
			{
				DbgPrint("Filter started!\n");
			}
		}
		else
		{
			FltCloseCommunicationPort(port);
		}
	}


	status = PsSetCreateProcessNotifyRoutineEx(ProcessNotifyRoutineEx, FALSE);
	if (!NT_SUCCESS(status))
	{
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Faild to PsSetCreateProcessNotifyRoutineEx .status : 0x%X \n", status);
	}
	status = InitObRegistration();
	if (!NT_SUCCESS(status))
	{
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Faild to ObRegistration .status : 0x%X \n", status);
	}
	DriverObject->DriverUnload = UnloadRoutine;

	return STATUS_SUCCESS;
}