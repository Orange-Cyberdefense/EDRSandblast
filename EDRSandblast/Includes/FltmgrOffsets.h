#pragma once


#include <Windows.h>

enum FltmgrOffsetType {
	FltGlobalsOffset,
	FrameListOffset,
	FrameList_rList,
	FrameLinks,
	RegisteredFilters,
	FilterListHead,
	FilterListCount,
	PrimaryLink,
	FilterName,
	ConnectionList,
	mList,
	mCount,
	MaxConnections,
	NumberOfConnections,
	srvPortCookie,
	MessageNotify,
	DisconnectNotify,
	ConnectNotify,
    _SUPPORTED_FLTMGR_OFFSETS_END
};

union FltmgrOffsets {
    // structure version of fltmgr.sys's offsets
    struct {
        DWORD64 FltGlobalsOffset;	// fltmgr.sys's FLTMGR!FltGlobals							symbol offset - type : _GLOBALS
        DWORD64 FrameListOffset;	// fltmgr.sys's FLTMGR!FltGlobals.FrameList					field offset  - type : _FLT_RESOURCE_LIST_HEAD
		DWORD64 FrameList_rList;	// fltmgr.sys's FLTMGR!FltGlobals.FrameList.rList			field offset  - type : _LIST_ENTRY
		DWORD64 FrameLinks;			// fltmgr.sys's _FLTP_FRAME.Links							field offset  - type : _LIST_ENTRY
		DWORD64 RegisteredFilters;  // fltmgr.sys's _FLTP_FRAME.RegisteredFilters				field offset  - type : _FLT_RESOURCE_LIST_HEAD
		DWORD64 FilterListHead;     // fltmgr.sys's _FLTP_FRAME.RegisteredFilters.rList			field offset  - type : _LIST_ENTRY
		DWORD64 FilterListCount;    // fltmgr.sys's _FLTP_FRAME.RegisteredFilters.rCount		field offset  - type : uint32_t
		DWORD64 PrimaryLink;        // fltmgr.sys's _FLT_FILTER.Base.PrimaryLink				field offset  - type : _LIST_ENTRY
		DWORD64 FilterName;		    // fltmgr.sys's _FLT_FILTER.Name							field offset  - type : _UNICODE_STRING 
		DWORD64 ConnectionList;     // fltmgr.sys's _FLT_FILTER.ConnectionList					field offset  - type : _FLT_MUTEX_LIST_HEAD 
		DWORD64 mList;              // fltmgr.sys's _FLT_MUTEX_LIST_HEAD.mList					field offset  - type : _LIST_ENTRY
		DWORD64 mCount;             // fltmgr.sys's _FLT_MUTEX_LIST_HEAD.mCount					field offset  - type : uint32_t
		DWORD64 MaxConnections;     // fltmgr.sys's _FLT_SERVER_PORT_OBJECT.MaxConnections		field offset  - type : uint32_t
		DWORD64 NumberOfConnections;// fltmgr.sys's _FLT_SERVER_PORT_OBJECT.NumberOfConnections	field offset  - type : uint32_t
		DWORD64 srvPortCookie;		// fltmgr.sys's _FLT_SERVER_PORT_OBJECT.Cookie				field offset  - type : void *
		DWORD64 MessageNotify;		// fltmgr.sys's _FLT_SERVER_PORT_OBJECT.MessageNotify		field offset  - type : proc *
		DWORD64	DisconnectNotify;	// fltmgr.sys's _FLT_SERVER_PORT_OBJECT.DisconnectNotify	field offset  - type : proc *
		DWORD64	ConnectNotify;		// fltmgr.sys's _FLT_SERVER_PORT_OBJECT.ConnectNotify		field offset  - type : proc *

    } st;

    // array version (usefull for code factoring)
    DWORD64 ar[_SUPPORTED_FLTMGR_OFFSETS_END];
};

union FltmgrOffsets g_fltmgrOffsets;

void LoadFltmgrOffsetsFromFile(TCHAR* fltmgrOffsetFilename);
LPTSTR GetFltmgrPath();
LPTSTR GetFltmgrVersion();
int FindKernelModule(_In_ PCCH ModuleName, _Out_ PULONG_PTR ModuleBase);
DWORD64 GetFltFieldOffset(enum FltmgrOffsetType fot);
DWORD64 dereferencePointer(DWORD64 pointerAddress);
void printFltName(USHORT firstFilterNameLenght, DWORD64 firstFilterNameAddress);
void PrintFltOffsets();
BOOL muteFilter(ULONG_PTR fltMgrBase, u_int FilterIndex);
void resetMaxConnections(ULONG_PTR firstFilterAddress);
BOOL printFltKdFrames(ULONG_PTR fltMgrBase, u_int FilterIndex);
void fromStep6(ULONG_PTR firstFilterAddress);

// Structures for hunting loaded kernel drivers
#define MAXIMUM_FILENAME_LENGTH 255 
typedef struct SYSTEM_MODULE {
	ULONG                Reserved1;
	ULONG                Reserved2;
#ifdef _WIN64
	ULONG				Reserved3;
#endif
	PVOID                ImageBaseAddress;
	ULONG                ImageSize;
	ULONG                Flags;
	WORD                 Id;
	WORD                 Rank;
	WORD                 w018;
	WORD                 NameOffset;
	CHAR                 Name[MAXIMUM_FILENAME_LENGTH];
}SYSTEM_MODULE, * PSYSTEM_MODULE;

typedef struct SYSTEM_MODULE_INFORMATION {
	ULONG                ModulesCount;
	SYSTEM_MODULE        Modules[1];
} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;

typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemModuleInformation = 11
} SYSTEM_INFORMATION_CLASS;

typedef NTSTATUS(WINAPI* PNtQuerySystemInformation)(
	__in SYSTEM_INFORMATION_CLASS SystemInformationClass,
	__inout PVOID SystemInformation,
	__in ULONG SystemInformationLength,
	__out_opt PULONG ReturnLength
	);
