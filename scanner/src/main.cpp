#define _WINSOCK_DEPRECATED_NO_WARNINGS 

#include <windows.h>
#include <stdio.h>
#include <lmcons.h>

#include <assert.h>
#include <strsafe.h>
#include <string>
#include <exception>

// Header required to search TCP table.
// #include <winsock2.h>
// #include <ws2tcpip.h>
#include <iphlpapi.h>

// Header reqeuired to get the process name by pid.
#include "tchar.h"
#include "psapi.h"

// Need to link with Iphlpapi.lib and Ws2_32.lib
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "Advapi32.lib")

#define MALLOC(x)		HeapAlloc(GetProcessHeap(), 0, (x))
#define FREE(x)			HeapFree(GetProcessHeap(), 0, (x))
#define SAFE_FREE(x)	do{if(x != nullptr) FREE(x); x = nullptr;}while(false)
#define SAFE_CLOSE(x)	do{if(x != nullptr) CloseHandle(x); x = nullptr;}while(false)
// Note: could also use malloc() and free()

typedef struct _LOOKUP_ROW {
	char			addr[128];
	unsigned short	port;
} LOOKUP_ROW, *PLOOKUP_ROW;

typedef struct _LOOKUP_TABLE {
	unsigned short	pid;
	LOOKUP_ROW		local;
	LOOKUP_ROW*		remote;
} LOOKUP_TABLE, *PLOOKUP_TABLE;


BOOL IsCurrentUserLocalAdministrator(void);



/*-------------------------------------------------------------------------

-
IsCurrentUserLocalAdministrator ()

This function checks the token of the calling thread to see if the caller
belongs to the Administrators group.

Return Value:
TRUE if the caller is an administrator on the local machine.
Otherwise, FALSE.
--------------------------------------------------------------------------*/
BOOL IsCurrentUserLocalAdministrator(void)
{
	BOOL   fReturn = FALSE;
	DWORD  dwStatus;
	DWORD  dwAccessMask;
	DWORD  dwAccessDesired;
	DWORD  dwACLSize;
	DWORD  dwStructureSize = sizeof(PRIVILEGE_SET);
	PACL   pACL = NULL;
	PSID   psidAdmin = NULL;

	HANDLE hToken = NULL;
	HANDLE hImpersonationToken = NULL;

	PRIVILEGE_SET   ps;
	GENERIC_MAPPING GenericMapping;

	PSECURITY_DESCRIPTOR     psdAdmin = NULL;
	SID_IDENTIFIER_AUTHORITY SystemSidAuthority = SECURITY_NT_AUTHORITY;


	/*
	Determine if the current thread is running as a user that is a member

	of
	the local admins group.  To do this, create a security descriptor

	that
	has a DACL which has an ACE that allows only local aministrators

	access.
	Then, call AccessCheck with the current thread's token and the

	security
	descriptor.  It will say whether the user could access an object if

	it
	had that security descriptor.  Note: you do not need to actually

	create
	the object.  Just checking access against the security descriptor

	alone
	will be sufficient.
	*/
	const DWORD ACCESS_READ = 1;
	const DWORD ACCESS_WRITE = 2;


	__try
	{

		/*
		AccessCheck() requires an impersonation token.  We first get a

		primary
		token and then create a duplicate impersonation token.  The
		impersonation token is not actually assigned to the thread, but is
		used in the call to AccessCheck.  Thus, this function itself never
		impersonates, but does use the identity of the thread.  If the

		thread
		was impersonating already, this function uses that impersonation

		context.
		*/
		if (!OpenThreadToken(GetCurrentThread(), TOKEN_DUPLICATE | TOKEN_QUERY,

			TRUE, &hToken))
		{
			if (GetLastError() != ERROR_NO_TOKEN)
				__leave;

			if (!OpenProcessToken(GetCurrentProcess(),

				TOKEN_DUPLICATE | TOKEN_QUERY, &hToken))
				__leave;
		}

		if (!DuplicateToken(hToken, SecurityImpersonation,

			&hImpersonationToken))
			__leave;


		/*
		Create the binary representation of the well-known SID that
		represents the local administrators group.  Then create the

		security
		descriptor and DACL with an ACE that allows only local admins

		access.
		After that, perform the access check.  This will determine whether
		the current user is a local admin.
		*/
		if (!AllocateAndInitializeSid(&SystemSidAuthority, 2,
			SECURITY_BUILTIN_DOMAIN_RID,
			DOMAIN_ALIAS_RID_ADMINS,
			0, 0, 0, 0, 0, 0, &psidAdmin))
			__leave;

		psdAdmin = LocalAlloc(LPTR, SECURITY_DESCRIPTOR_MIN_LENGTH);
		if (psdAdmin == NULL)
			__leave;

		if (!InitializeSecurityDescriptor(psdAdmin,

			SECURITY_DESCRIPTOR_REVISION))
			__leave;

		// Compute size needed for the ACL.
		dwACLSize = sizeof(ACL) + sizeof(ACCESS_ALLOWED_ACE) +
			GetLengthSid(psidAdmin) - sizeof(DWORD);

		pACL = (PACL)LocalAlloc(LPTR, dwACLSize);
		if (pACL == NULL)
			__leave;

		if (!InitializeAcl(pACL, dwACLSize, ACL_REVISION2))
			__leave;

		dwAccessMask = ACCESS_READ | ACCESS_WRITE;

		if (!AddAccessAllowedAce(pACL, ACL_REVISION2, dwAccessMask,

			psidAdmin))
			__leave;

		if (!SetSecurityDescriptorDacl(psdAdmin, TRUE, pACL, FALSE))
			__leave;

		/*
		AccessCheck validates a security descriptor somewhat; set the

		group
		and owner so that enough of the security descriptor is filled out

		to
		make AccessCheck happy.
		*/
		SetSecurityDescriptorGroup(psdAdmin, psidAdmin, FALSE);
		SetSecurityDescriptorOwner(psdAdmin, psidAdmin, FALSE);

		if (!IsValidSecurityDescriptor(psdAdmin))
			__leave;

		dwAccessDesired = ACCESS_READ;

		/*
		Initialize GenericMapping structure even though you
		do not use generic rights.
		*/
		GenericMapping.GenericRead = ACCESS_READ;
		GenericMapping.GenericWrite = ACCESS_WRITE;
		GenericMapping.GenericExecute = 0;
		GenericMapping.GenericAll = ACCESS_READ | ACCESS_WRITE;

		if (!AccessCheck(psdAdmin, hImpersonationToken, dwAccessDesired,
			&GenericMapping, &ps, &dwStructureSize, &dwStatus,
			&fReturn))
		{
			fReturn = FALSE;
			__leave;
		}
	}
	__finally
	{
		// Clean up.
		if (pACL) LocalFree(pACL);
		if (psdAdmin) LocalFree(psdAdmin);
		if (psidAdmin) FreeSid(psidAdmin);
		if (hImpersonationToken) CloseHandle(hImpersonationToken);
		if (hToken) CloseHandle(hToken);
	}

	return fReturn;
}

BOOL IsElevated() {
	BOOL fRet = FALSE;
	HANDLE hToken = NULL;
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
		TOKEN_ELEVATION Elevation;
		DWORD cbSize = sizeof(TOKEN_ELEVATION);
		if (GetTokenInformation(hToken, TokenElevation, &Elevation, sizeof(Elevation), &cbSize)) {
			fRet = Elevation.TokenIsElevated;
		}
	}
	if (hToken) {
		CloseHandle(hToken);
	}
	return fRet;
}

bool BuildLookupTable(_Out_ PLOOKUP_TABLE table, _Inout_ size_t* size);

void GetError(LPTSTR lpszFunction) {
	LPVOID lpMsgBuf;
	LPVOID lpDisplayBuf;
	DWORD dw = GetLastError();

	FormatMessage(
		FORMAT_MESSAGE_ALLOCATE_BUFFER |
		FORMAT_MESSAGE_FROM_SYSTEM |
		FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		dw,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		(LPTSTR)&lpMsgBuf,
		0, NULL);

	// Display the error message and exit the process

	lpDisplayBuf = (LPVOID)LocalAlloc(LMEM_ZEROINIT,
		(lstrlen((LPCTSTR)lpMsgBuf) + lstrlen((LPCTSTR)lpszFunction) + 40) * sizeof(TCHAR));
	StringCchPrintf((LPTSTR)lpDisplayBuf,
		LocalSize(lpDisplayBuf) / sizeof(TCHAR),
		TEXT("%s failed with error %d: %s"),
		lpszFunction, dw, lpMsgBuf);
	MessageBox(NULL, (LPCTSTR)lpDisplayBuf, TEXT("Error"), MB_OK);

	LocalFree(lpMsgBuf);
	LocalFree(lpDisplayBuf);
	ExitProcess(dw);

	return;
}

int main()
{
	if (IsCurrentUserLocalAdministrator())
		printf("You are an administrator\n");
	else
		printf("You are not an administrator\n");

	HANDLE				process = nullptr;
	HANDLE				access = nullptr;
	TOKEN_PRIVILEGES	privilege;
	ULONG				size = 0;
	BOOL				retVal;
	LUID				luid;

	process = GetCurrentProcess();

	if (OpenProcessToken(process, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &access) == false) {
		SAFE_CLOSE(process);
		return 1;
	}

	retVal = LookupPrivilegeValue(NULL, "SeDebugPrivilege", &luid);
	if (retVal == FALSE) {
		GetError("LookupPrivilegeValue");
		SAFE_CLOSE(access);
		SAFE_CLOSE(process);
		return 2;
	}

	privilege.PrivilegeCount = 1;
	privilege.Privileges[0].Luid = luid;
	privilege.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	retVal = AdjustTokenPrivileges(access, FALSE, &privilege, sizeof(privilege), NULL, NULL);
	if (retVal == FALSE) {
		GetError("AdjustTokenPrivileges");
		SAFE_CLOSE(access);
		SAFE_CLOSE(process);
		return 4;
	}

	// enter code here.

	PLOOKUP_TABLE	table = nullptr;
	size_t			table_size = sizeof(LOOKUP_TABLE);

	table = (LOOKUP_TABLE *)MALLOC(table_size);

	bool ret = BuildLookupTable(table, &table_size);
	printf("Return: %d\n", ret);

	SAFE_FREE(table);

	/////////////////////////////////////////////////

	privilege.PrivilegeCount = 1;
	privilege.Privileges[0].Luid = luid;
	privilege.Privileges[0].Attributes = 0;

	retVal = AdjustTokenPrivileges(access, FALSE, &privilege, sizeof(privilege), NULL, NULL);
	if (retVal == FALSE) {
		GetError("AdjustTokenPrivileges");
		SAFE_CLOSE(access);
		SAFE_CLOSE(process);
	}

	SAFE_CLOSE(access);
	SAFE_CLOSE(process);

	getchar();

	return 0;
}
bool BuildLookupTable(_Out_ PLOOKUP_TABLE table, _Inout_ size_t* size) {
	if (table == nullptr)
		return false;

	PMIB_UDPTABLE_OWNER_PID	pUdpTable = nullptr;
	PMIB_TCPTABLE2			pTcpTable = nullptr;
	ULONG					ulSize;
	DWORD					dwRetVal;

	char			szLocalAddr[128];
	char			szRemoteAddr[128];
	struct in_addr	IpAddr;

	// Get TCP Table.
	pTcpTable = (MIB_TCPTABLE2 *)MALLOC(sizeof(MIB_TCPTABLE2));
	if (pTcpTable == nullptr) // Memory exhausted.
		return false;

	// Fit TCP table size.
	ulSize = sizeof(MIB_TCPTABLE2);
	dwRetVal = GetTcpTable2(pTcpTable, &ulSize, TRUE);
	if (dwRetVal == ERROR_INSUFFICIENT_BUFFER) {
		SAFE_FREE(pTcpTable);
		pTcpTable = (MIB_TCPTABLE2 *)MALLOC(ulSize);
		if (pTcpTable == nullptr) // Memory exhuasted.
			return false;
	}

	// Retreive TCP table.
	dwRetVal = GetTcpTable2(pTcpTable, &ulSize, TRUE);
	if (dwRetVal == NO_ERROR) {
		printf("\tNumber of TCP entries: %d\n", (int)pTcpTable->dwNumEntries);
		for (unsigned int i = 0; i < (unsigned int)pTcpTable->dwNumEntries; i++) {
			if (i != 0U)
				printf("\n");

			// Local addr in ipv4.
			IpAddr.S_un.S_addr = (u_long)pTcpTable->table[i].dwLocalAddr;
			strcpy_s(szLocalAddr, sizeof(szLocalAddr), inet_ntoa(IpAddr));
			printf("\tTCP[%d] Local Addr: %s\n", i, szLocalAddr);

			// Local port.
			printf("\tTCP[%d] Local Port: %d \n", i,
				ntohs((u_short)pTcpTable->table[i].dwLocalPort));

			// Remote addr in ipv4.
			IpAddr.S_un.S_addr = (u_long)pTcpTable->table[i].dwRemoteAddr;
			strcpy_s(szRemoteAddr, sizeof(szRemoteAddr), inet_ntoa(IpAddr));
			printf("\tTCP[%d] Remote Addr: %s\n", i, szRemoteAddr);

			// Remote port.
			printf("\tTCP[%d] Remote Port: %d\n", i,
				ntohs((u_short)pTcpTable->table[i].dwRemotePort));

			// Owning process' id.
			printf("\tTCP[%d] Owning PID: %d\n", i, pTcpTable->table[i].dwOwningPid);


			TCHAR szProcessName[MAX_PATH] = TEXT("<unknown>");

			// Get a handle to the process.

			HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION |
				PROCESS_VM_READ,
				FALSE, pTcpTable->table[i].dwOwningPid);

			// Get the process name.
			if (NULL != hProcess)
			{
				HMODULE hMod;
				DWORD cbNeeded;

				if (EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeeded))
				{
					GetModuleBaseName(hProcess, hMod, szProcessName,
						sizeof(szProcessName) / sizeof(TCHAR));
				}
			}
			else {
				strcpy_s(szProcessName, sizeof(TEXT("<invalid>")), TEXT("<invalid>"));
			}

			// Print the process name and identifier.

			_tprintf(TEXT("\t%s  (PID: %u)\n"), szProcessName, pTcpTable->table[i].dwOwningPid);

			// Release the handle to the process.

			CloseHandle(hProcess);
		}
	}
	else {
		SAFE_FREE(pTcpTable);
		return false;
	}

	// Success over TCP table.
	SAFE_FREE(pTcpTable);
	assert(pTcpTable == nullptr);

	// Get UDP table.
	pUdpTable = (MIB_UDPTABLE_OWNER_PID *)MALLOC(sizeof(MIB_UDPTABLE_OWNER_PID));
	if (pUdpTable == nullptr) // Memory exhausted.
		return false;

	// Fit UDP table size.
	ulSize = sizeof(MIB_UDPTABLE_OWNER_PID);
	dwRetVal = GetExtendedUdpTable(pUdpTable, &ulSize, TRUE, AF_INET, UDP_TABLE_CLASS::UDP_TABLE_OWNER_PID, 0);
	if (dwRetVal == ERROR_INSUFFICIENT_BUFFER) {
		SAFE_FREE(pUdpTable);
		pUdpTable = (MIB_UDPTABLE_OWNER_PID *)MALLOC(ulSize);
		if (pUdpTable == nullptr) // Memory exhuasted.
			return false;
	}
	else if (dwRetVal == ERROR_INVALID_PARAMETER) {
		SAFE_FREE(pUdpTable);
		return false;
	}

	// Retreive TCP table.
	dwRetVal = GetExtendedUdpTable(pUdpTable, &ulSize, TRUE, AF_INET, UDP_TABLE_CLASS::UDP_TABLE_OWNER_PID, 0);
	if (dwRetVal == NO_ERROR) {
		printf("\tNumber of UDP entries: %d\n", (int)pUdpTable->dwNumEntries);
		for (unsigned int i = 0; i < (unsigned int)pUdpTable->dwNumEntries; i++) {
			if (i != 0U)
				printf("\n");

			// Local addr in ipv4.
			IpAddr.S_un.S_addr = (u_long)pUdpTable->table[i].dwLocalAddr;
			strcpy_s(szLocalAddr, sizeof(szLocalAddr), inet_ntoa(IpAddr));
			printf("\tUDP[%d] Local Addr: %s\n", i, szLocalAddr);

			// Local port.
			printf("\tUDP[%d] Local Port: %d \n", i,
				ntohs((u_short)pUdpTable->table[i].dwLocalPort));

			// Owning process' id.
			printf("\tUDP[%d] Owning PID: %d\n", i, pUdpTable->table[i].dwOwningPid);

			TCHAR szProcessName[MAX_PATH] = TEXT("<unknown>");

			// Get a handle to the process.
			HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION |
				PROCESS_VM_READ,
				FALSE, pUdpTable->table[i].dwOwningPid);

			// Get the process name.
			if (NULL != hProcess)
			{
				HMODULE hMod;
				DWORD cbNeeded;

				if (EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeeded))
				{
					GetModuleBaseName(hProcess, hMod, szProcessName,
						sizeof(szProcessName) / sizeof(TCHAR));
				}
			}
			else {
				strcpy_s(szProcessName, sizeof(TEXT("<invalid>")), TEXT("<invalid>"));
			}


			// Print the process name and identifier.
			_tprintf(TEXT("\t%s  (PID: %u)\n"), szProcessName, pUdpTable->table[i].dwOwningPid);

			// Release the handle to the process.
			CloseHandle(hProcess);
		}
	}
	else {
		SAFE_FREE(pUdpTable);
		return false;
	}

	SAFE_FREE(pUdpTable);

	assert(pUdpTable == nullptr);

	return true;
}