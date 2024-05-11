#include <iostream>
#include <windows.h>
#include <string>
#include "errors.h"
#include <stdio.h>
#include <tchar.h>
#include <psapi.h>
#include <fcntl.h>
#include <io.h>
#include <fstream>
using namespace std;

struct Process {
	DWORD pid;
	string name;
};

int closeInjector(int error);
int findProcess(Process* target, bool byPid, DWORD pid, string pName);
int findProcess(Process* target, DWORD pid);
int findProcess(Process* target, string pName);
Process parseProcess(DWORD processID);
int injectDll(DWORD pid, string dllLocation);
bool RedirectConsoleIO(); // https://stackoverflow.com/a/55875595
unique_ptr<string> getArgumentValue(string argument, int argc, char** argv);
int getArgumentIndex(string argument, int argc, char** argv);
bool hasArgument(string argument, int argc, char** argv, bool withValue = false);

int main(int argc, char** argv) {
	bool console = false;
	string dllFile = "";
	bool byPid = false;
	DWORD pid = 0;
	string pName;
	Process target;
	int result;
	if (!(console = AttachConsole(ATTACH_PARENT_PROCESS))) {
		if (hasArgument("c", argc, argv)) {
			console = AllocConsole();
		}
	}
	if (console) {
		RedirectConsoleIO();
	}

	if (argc == 1) {
		return closeInjector(INJECTOR_NO_PARAMS);
	}
	else if (hasArgument("h", argc, argv)) {
			cout << "DLLInjector.exe -f <.dll file location> [-n process name]/[-p pid]" << endl;
			cout << "-h for help" << endl;
			return closeInjector(INJECTOR_OK);
	}
	else if (hasArgument("f", argc, argv, true) && (hasArgument("n", argc, argv, true) || hasArgument("p", argc, argv, true))) {
		dllFile = *getArgumentValue("f", argc, argv);
		if (hasArgument("n", argc, argv, true)) {
			pName = *getArgumentValue("n", argc, argv);
		}
		else {
			try {
				pid = atoi(getArgumentValue("p", argc, argv)->c_str());
				byPid = true;
			}
			catch (...) {
				return closeInjector(INJECTOR_INVALID_PARAMS);
			}
		}
	}
	else {
		return closeInjector(INJECTOR_INVALID_PARAMS);
	}
	//cout << "bypid" << byPid << endl;
	//cout << pid << "pid" << endl;
	result = findProcess(&target, byPid, pid, pName);
	if (result != 0) {
		return closeInjector(result);
	}
	cout << "Proccess found " << target.pid << " " << target.name << endl;
	result = injectDll(target.pid, dllFile);
	return closeInjector(result);
}

//dumb arg checker
bool hasArgument(string argument, int argc, char** argv, bool withValue) {
	int index = getArgumentIndex(argument, argc, argv);
	return index != -1 && (!withValue || argc > index + 1);
}

int getArgumentIndex(string argument, int argc, char** argv) {
	for (int i = 1; i < argc; i++) {
		if (argv[i][0] != '-') {
			continue;
		}
		string arg = string(argv[i]).substr(1);
		if (argument == arg) {
			return i;
		}
	}
	return -1;
}

unique_ptr<string> getArgumentValue(string argument, int argc, char** argv) {
	int index = getArgumentIndex(argument, argc, argv);
	if (index != -1 && argc > index + 1) {
		return make_unique<string>(argv[index + 1]);
	}
	return NULL;
}

bool RedirectConsoleIO()
{
	bool result = true;
	FILE* fp;

	// Redirect STDIN if the console has an input handle
	if (GetStdHandle(STD_INPUT_HANDLE) != INVALID_HANDLE_VALUE)
		if (freopen_s(&fp, "CONIN$", "r", stdin) != 0)
			result = false;
		else
			setvbuf(stdin, NULL, _IONBF, 0);

	// Redirect STDOUT if the console has an output handle
	if (GetStdHandle(STD_OUTPUT_HANDLE) != INVALID_HANDLE_VALUE)
		if (freopen_s(&fp, "CONOUT$", "w", stdout) != 0)
			result = false;
		else
			setvbuf(stdout, NULL, _IONBF, 0);

	// Redirect STDERR if the console has an error handle
	if (GetStdHandle(STD_ERROR_HANDLE) != INVALID_HANDLE_VALUE)
		if (freopen_s(&fp, "CONOUT$", "w", stderr) != 0)
			result = false;
		else
			setvbuf(stderr, NULL, _IONBF, 0);

	// Make C++ standard streams point to console as well.
	ios::sync_with_stdio(true);

	// Clear the error state for each of the C++ standard streams.
	std::wcout.clear();
	std::cout.clear();
	std::wcerr.clear();
	std::cerr.clear();
	std::wcin.clear();
	std::cin.clear();

	return result;
}

int closeInjector(int error) {
	switch (error) {
	case INJECTOR_OK:
		break;
	case INJECTOR_NO_PARAMS:
		cout << "ERROR: No parameters specified" << endl;
		break;
	case INJECTOR_INVALID_PARAMS:
		cout << "ERROR: Invalid parameters specified" << endl;
		break;
	case INJECTOR_PROCESS_NOT_FOUND:
		cout << "ERROR: Process not found" << endl;
		break;
	case INJECTOR_DLL_NOT_FOUND:
		cout << "ERROR: DLL not found" << endl;
		break;
	case INJECTOR_FAILED_TO_GET_PROCESSES:
		cout << "ERROR: Failed to get processes" << endl;
		break;
	case INJECTOR_FAILED_TO_OPEN_PROCESS:
		cout << "ERROR: Failed to get process handle" << endl;
		break;
	case INJECTOR_FAILED_TO_INJECT:
		cout << "ERROR: Failed to inject dll" << endl;
		break;
	}
	return error;
}

Process parseProcess(DWORD processID)
{
	CHAR szProcessName[MAX_PATH] = "<unknown>";
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION |
		PROCESS_VM_READ,
		FALSE, processID);

	// Get the process name.

	if (NULL != hProcess)
	{
		HMODULE hMod;
		DWORD cbNeeded;

		if (EnumProcessModules(hProcess, &hMod, sizeof(hMod),
			&cbNeeded))
		{
			GetModuleBaseNameA(hProcess, hMod, szProcessName,
				sizeof(szProcessName) / sizeof(CHAR));
		}
		CloseHandle(hProcess);
	}

	// Print the process name and identifier.

	// Release the handle to the process.
	return { processID, string(szProcessName)};
}

int findProcess(Process* target, bool byPid, DWORD pid, string pName) {
	DWORD aProcesses[1024], cbNeeded, cProcesses;
	unsigned int i;

	if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded))
	{
		return INJECTOR_FAILED_TO_GET_PROCESSES;
	}

	// Calculate how many process identifiers were returned.

	cProcesses = cbNeeded / sizeof(DWORD);

	// Print the name and process identifier for each process.

	for (i = 0; i < cProcesses; i++)
	{
		if (aProcesses[i] != 0)
		{
			Process process = parseProcess(aProcesses[i]);
			if (byPid && process.pid == pid) {
				*target = process;
				return 0;
			}
			else if (!byPid && process.name == pName) {
				*target = process;
				return 0;
			}
		}
	}
	return INJECTOR_PROCESS_NOT_FOUND;
}
int findProcess(Process* target, DWORD pid) {
	return findProcess(target, true, pid, "");
}
int findProcess(Process* target, string pName) {
	return findProcess(target, false, -1, pName);
}

int injectDll(DWORD pid, string dllLocation) {
	HANDLE hThread;
	void* pLibRemote;   // The address (in the remote process)
						// where szLibPath will be copied to;
	DWORD hLibModule;   // Base address of loaded module (==HMODULE);

	// initialize szLibPath
	//...PROCESS_CREATE_THREAD, PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION, PROCESS_VM_WRITE, and PROCESS_VM_READ

	// 1. Allocate memory in the remote process for szLibPath
	// 2. Write szLibPath to the allocated memory

	HANDLE hProcess = OpenProcess(
		PROCESS_CREATE_THREAD |
		PROCESS_QUERY_INFORMATION |
		PROCESS_VM_OPERATION |
		PROCESS_VM_WRITE |
		PROCESS_VM_READ,
		FALSE, pid);
	if (hProcess == NULL) {
		return INJECTOR_FAILED_TO_OPEN_PROCESS;
	}
	pLibRemote = VirtualAllocEx(hProcess, NULL, dllLocation.length() + 1,
		MEM_COMMIT, PAGE_READWRITE);
	if (pLibRemote == NULL) {
		cout << "Failed to allocate memory" << endl;
		return INJECTOR_FAILED_TO_INJECT;
	}
	
	WriteProcessMemory(hProcess, pLibRemote, (void*)dllLocation.c_str(),
		dllLocation.length() + 1, NULL);


	// Load dll into the remote process
	hThread = CreateRemoteThread(hProcess, NULL, 0,
		(LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleA("Kernel32"), "LoadLibraryA"),
		pLibRemote, 0, NULL);

	if (hThread == NULL) {
		cout << "Failed to Create Remote Thread (" << GetLastError() << ")" << endl;
		return INJECTOR_FAILED_TO_INJECT;
	}

	WaitForSingleObject(hThread, INFINITE);

	// Get handle of the loaded module
	GetExitCodeThread(hThread, &hLibModule);
	if (hLibModule == NULL) {
		hLibModule = -1;
		cout << "LoadLibraryA failed" << endl;
		return INJECTOR_FAILED_TO_INJECT;
	}
	else {
		cout << hex << "0x" << hLibModule << endl;
	}
	// Clean up
	CloseHandle(hThread);
	VirtualFreeEx(hProcess, pLibRemote,
		dllLocation.length() + 1, MEM_RELEASE);

	return INJECTOR_OK;
}