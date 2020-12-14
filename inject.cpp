/*
Written by: SaEeD
Description: Injecting DLL to Target process using Process Id or Process name
*/
#include <iostream>
#include <Windows.h>
#include <tlhelp32.h>
//Library needed by Linker to check file existance
#pragma comment(lib, "Shlwapi.lib")

using namespace std;

int getProcID(const string& p_name);
bool InjectDLL(const int &pid, const string &DLL_Path);
void usage();

int main()
{
    STARTUPINFO si;
    PROCESS_INFORMATION pi;

    ZeroMemory( &si, sizeof(si) );
    si.cb = sizeof(si);
    ZeroMemory( &pi, sizeof(pi) );
    // Start the child process. 
    if( !CreateProcess("D:\\Game\\MapleLove\\MapleLove\\MapleStory.exe",   // No module name (use command line)
        " GameLaunching 8.31.99.141 8484",        // Command line
        NULL,           // Process handle not inheritable
        NULL,           // Thread handle not inheritable
        FALSE,          // Set handle inheritance to FALSE
        0,              // No creation flags
        NULL,           // Use parent's environment block
        NULL,           // Use parent's starting directory 
        &si,            // Pointer to STARTUPINFO structure
        &pi )           // Pointer to PROCESS_INFORMATION structure
    ) 
    {
        printf( "CreateProcess failed (%d).\n", GetLastError() );
        return 1;
    }
	InjectDLL(getProcID("MapleStory.exe"),"D:\\Game\\MapleLove\\MapleLove\\MapleLove.dll");
	
	Sleep(1000);

	InjectDLL(getProcID("MapleStory.exe"),"C:\\Users\\ad\\Downloads\\Angel Processor v145.2.1_mpgh.net\\AngelProcessor.dll");
    Sleep(10000);
	//InjectDLL(getProcID("MapleStory.exe"),"C:\\Users\\ad\\Downloads\\Angel Processor v145.2.1_mpgh.net\\multi.dll");
    
	// Wait until child process exits.
    WaitForSingleObject( pi.hProcess, INFINITE );
	printf( "STEP 2\n");
    // Close process and thread handles. 
    CloseHandle( pi.hProcess );
    CloseHandle( pi.hThread );
}
//-----------------------------------------------------------
// Get Process ID by its name
//-----------------------------------------------------------
int getProcID(const string& p_name)
{
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 structprocsnapshot = { 0 };

	structprocsnapshot.dwSize = sizeof(PROCESSENTRY32);

	if (snapshot == INVALID_HANDLE_VALUE)return 0;
	if (Process32First(snapshot, &structprocsnapshot) == FALSE)return 0;
	DWORD checked;
	while (Process32Next(snapshot, &structprocsnapshot))
	{
		if (!strcmp(structprocsnapshot.szExeFile, p_name.c_str()))
		{
			
			cout << "[+]Process name Check is: " << p_name << "\n[+]Process ID: " << structprocsnapshot.th32ProcessID << endl;
			//HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, structprocsnapshot.th32ProcessID);
			//if (hProc == NULL)
			//{
			//	cerr << "[!]Fail to open target process!" << endl;
			//	continue;
			//}
			//else 
			//{
			//	CloseHandle(snapshot);
			//	return structprocsnapshot.th32ProcessID;
			//}
			checked = structprocsnapshot.th32ProcessID;
		}
	}
	CloseHandle(snapshot);
	//cerr << "[!]Unable to find Process ID" << endl;
	return checked;

}
//-----------------------------------------------------------
// Inject DLL to target process
//-----------------------------------------------------------
bool InjectDLL(const int &pid, const string &DLL_Path)
{
	long dll_size = DLL_Path.length() + 1;
	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	cout << "[+]Now Injecting "<<DLL_Path<<endl;
	if (hProc == NULL)
	{
		cerr << "[!]Fail to open target process!" << endl;
		return false;
	}
	cout << "[+]Opening Target Process..." << endl;

	LPVOID MyAlloc = VirtualAllocEx(hProc, NULL, dll_size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (MyAlloc == NULL)
	{
		cerr << "[!]Fail to allocate memory in Target Process." << endl;
		return false;
	}

	cout << "[+]Allocating memory in Targer Process." << endl;
	int IsWriteOK = WriteProcessMemory(hProc , MyAlloc, DLL_Path.c_str() , dll_size, 0);
	if (IsWriteOK == 0)
	{
		cerr << "[!]Fail to write in Target Process memory." << endl;
		return false;
	}
	cout << "[+]Creating Remote Thread in Target Process" << endl;

	DWORD dWord;
	LPTHREAD_START_ROUTINE addrLoadLibrary = (LPTHREAD_START_ROUTINE)GetProcAddress(LoadLibrary("kernel32"), "LoadLibraryA");
	HANDLE ThreadReturn = CreateRemoteThread(hProc, NULL, 0, addrLoadLibrary, MyAlloc, 0, &dWord);
	if (ThreadReturn == NULL)
	{
		cerr << "[!]Fail to create Remote Thread" << endl;
		return false;
	}

	if ((hProc != NULL) && (MyAlloc != NULL) && (IsWriteOK != ERROR_INVALID_HANDLE) && (ThreadReturn != NULL))
	{
		cout << "[+]DLL Successfully Injected :)" << endl;
		return true;
	}

	return false;
}