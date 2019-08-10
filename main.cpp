#include <Windows.h>
#include <iostream>

#define DEBUG_MESSAGE // allow debug messages?
#define Debugf(fmt, ...) printf( "[-] " fmt, __VA_ARGS__ )
 

struct ScopedMemoryProtect
{
	//
	// We will need to adjust memory protection at the function ptr so we can replace it with our own
	//
	ScopedMemoryProtect( PVOID pMemAddress, DWORD dwNewProtection = PAGE_READWRITE ) : m_pMemAddress( pMemAddress ) {
		VirtualProtect( m_pMemAddress, sizeof( PVOID ), dwNewProtection, &m_dwOldProtection );
	}

	~ScopedMemoryProtect() { 
		VirtualProtect( m_pMemAddress, sizeof( PVOID ), m_dwOldProtection, &m_dwOldProtection );
	}

private:
	PVOID m_pMemAddress;
	DWORD m_dwOldProtection;
};
 

bool ApplyWinAPIHook( PVOID pApiFunction, PVOID pHookFunction, PVOID *ppOriginalApiFunction )
{   
	PUCHAR pApiFunctionStart = static_cast< PUCHAR >( pApiFunction );
	
	//
	// We need to search for a call/jmp
	//
	for ( int i = 0; i < 0x64; i++ )
	{
		switch ( pApiFunctionStart[ i ] )
		{
		case 0xFF: // jmp/call dword ptr []
		{
			switch ( pApiFunctionStart[ i + 1 ] )
			{
			case 0x15:
			case 0x25:
			{
#ifdef DEBUG_MESSAGE
				Debugf( "Detected far CALL/JMP => 0x%p (", &pApiFunctionStart[ i ] );
				for ( int b = 0; b < 6; b++ )
					printf( "%02X ", pApiFunctionStart[ i + b ] );
				printf( "\b).\n" );
#endif

				//
				// Resolve the relative address 
				//
				UINT32 uiAddress = *reinterpret_cast< UINT32 * >( &pApiFunctionStart[ i + 2 ] );
			
#ifdef DEBUG_MESSAGE
				Debugf( "Relative address => 0x%X.\n", uiAddress );
#endif

				//
				// Get the address that holds the function ptr by using the relative address (instruction_end + rel)
				//
#ifdef _WIN64
				PVOID pFuncPtrAddress = static_cast< PVOID >( ( &pApiFunctionStart[ i ] + 0x6 ) + uiAddress );
#else 
				PVOID pFuncPtrAddress = reinterpret_cast< PVOID >( uiAddress );
#endif

#ifdef DEBUG_MESSAGE
				Debugf( "Found function pointer => 0x%p.\n", pFuncPtrAddress );
#endif

				//
				// Store the original function (if possible)
				//
				if ( ppOriginalApiFunction )
					*ppOriginalApiFunction = *static_cast< PVOID * >( pFuncPtrAddress );
			
				//
				// Perform the hook
				//
				{
					ScopedMemoryProtect mp( pFuncPtrAddress ); 
					*static_cast< PVOID * >( pFuncPtrAddress ) = pHookFunction;
				}

#ifdef DEBUG_MESSAGE
				Debugf( "Replaced function => 0x%p.\n", pHookFunction );
#endif

				return true;
			}

			}
		}

		}
	}

	return false;
}

bool DetachWinAPIHook( PVOID pApiFunction, PVOID pOrigSyscallHookFunction )
{
	return ApplyWinAPIHook( pApiFunction, pOrigSyscallHookFunction, NULL );
}


NTSTATUS( NTAPI *g_pfnNtUserSetCursorPos )( int, int, int ) = NULL;
NTSTATUS NTAPI NtUserSetCursorPos_Hook( int x, int y, int unk )
{
	printf( "[!] NtSetCursorPos_Hook.\n" ); 
	return g_pfnNtUserSetCursorPos( x, y, unk );
}

BOOL( WINAPI* g_pfnWriteConsoleA )( HANDLE, CONST VOID*, DWORD, LPDWORD, LPVOID ) = NULL;
BOOL WINAPI WriteConsoleA_Hook( HANDLE hConsoleOutput, CONST VOID* lpBuffer, DWORD nNumberOfCharsToWrite, LPDWORD lpNumberOfCharsWritten, LPVOID lpReserved )
{
	return g_pfnWriteConsoleA( hConsoleOutput, "[!] WriteConsoleA_Hook\n", strlen( "[!] WriteConsoleA_Hook\n" ), lpNumberOfCharsWritten, lpReserved );
}

int main()
{  
	SetConsoleTitleA( "Hooking Windows APIs - https://github.com/ayyMike" );

	// WARNING: Will not work for all APIs (as is)
	// NOTE: You are not hooking the API per se, you are hooking what the API CALLS.
	// e.g SetPhysicalCursorPos WINAPI will call NtUserSetCursorPos
	// If you are confused what the API will call, pop open the appropriate DLL in IDA/Etc and check it out 
	 
	// SetPhysicalCursorPos - user32.dll (calls NtUserSetCursorPos)
	if ( ApplyWinAPIHook( SetPhysicalCursorPos, NtUserSetCursorPos_Hook, ( PVOID *)&g_pfnNtUserSetCursorPos ) )
	{
		printf( "[!] Hooked NtUserSetCursorPos .. calling SetPhysicalCursorPos.\n" );
		
		//
		// Call SetPhysicalCursorPos to ensure that our hook runs
		//
		SetPhysicalCursorPos( 100, 100 );
	}

	// WriteConsoleA - kernel32.dll (calls WriteConsoleA)
	if ( ApplyWinAPIHook( WriteConsoleA, WriteConsoleA_Hook, ( PVOID* )&g_pfnWriteConsoleA ) )
	{
		printf( "[!] Hooked WriteConsoleA .. calling WriteConsoleA\n" );

		//
		// Call WriteConsoleA to ensure that our hook runs
		//
		std::string strTest = "This is a test.\n";
		DWORD dwNumCharsWritten = 0;
		// Will print "[!] WriteConsoleA_Hook\n" instead of "This is a test.\n"
		WriteConsoleA( GetStdHandle( STD_OUTPUT_HANDLE ), strTest.c_str(), strTest.length(), &dwNumCharsWritten, NULL ); 
	}

	//
	// Remove hooks.
	// 
	DetachWinAPIHook( SetPhysicalCursorPos, g_pfnNtUserSetCursorPos );
	DetachWinAPIHook( WriteConsoleA, g_pfnWriteConsoleA );

	return system("pause");
} 
