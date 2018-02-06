#include <ntddk.h>

VOID Unload(IN PDRIVER_OBJECT DriverObject)
{
	DbgPrint("%s\n", "Driver unloaded.");
	DriverObject;
	return;
}

NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING regPath)
{
	DbgPrint("%s\n", "Driver has been loaded.");
	(*DriverObject).DriverUnload = Unload;
	regPath;
	return (STATUS_SUCCESS);
}