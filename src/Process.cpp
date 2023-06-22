#include "Process.h"
#include <Windows.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include "imagehlp.h"
#include <winternl.h>
#include <map>

#pragma comment(lib, "imagehlp.lib")
#pragma comment(lib, "ntdll.lib")

using PID = DWORD;
using THREAD_BASE = int;
static_assert(sizeof(THREAD_BASE) == sizeof(void*), "Invalid THREAD_BASE size. It should cover a pointer");

struct ProcessData {
	PID pid;
	HANDLE procHandle;
	bool attached;
	
	std::map<int, HANDLE>* threads;
	std::map<int, THREAD_BASE>* threadBases;
};

const char* ProcessModuleExportedFunction::GetName() {
	return name;
}

void* ProcessModuleExportedFunction::GetLocation() {
	return ptr;
}

ProcessModuleExportedFunction::ProcessModuleExportedFunction(const char* name, void* ptr) {
	this->name = name;
	this->ptr = ptr;
}

ProcessModuleExportedFunction::~ProcessModuleExportedFunction() {

}

const char* ProcessModule::GetName() {
	return name;
}

void* ProcessModule::GetEntryPoint() {
	return entryPoint;
}

void* ProcessModule::GetBaseAddress() {
	return baseAddress;
}

unsigned int ProcessModule::GetModuleSize() {
	return size;
}

ProcessModule::ProcessModule(const char* name, void* entryPoint, void* baseAddress, unsigned int size) {
	this->name = name;
	this->entryPoint = entryPoint;
	this->baseAddress = baseAddress;
	this->size = size;
}

ProcessModule::~ProcessModule() {

}

bool ProcessModule::ForAllExportedFunctions2(void(*cb)(void*, ProcessModuleExportedFunction*), void* instance) {
	HMODULE mod = reinterpret_cast<HMODULE>(this->ptrHmod);
	HANDLE procHandle = reinterpret_cast<HANDLE>(this->procHandle);

	CHAR cstr[MAX_PATH];
	if (!GetModuleFileNameExA(procHandle, mod, cstr, sizeof(cstr) / sizeof(cstr[0]))) {
		LOG_ERROR("Call to GetModuleFileName failed: %d", GetLastError());
		return false;
	}

	_IMAGE_EXPORT_DIRECTORY* ImageExportDirectory;
	unsigned long cDirSize;
	_LOADED_IMAGE LoadedImage;
	if (MapAndLoad(cstr, NULL, &LoadedImage, TRUE, TRUE)) {
		ImageExportDirectory = (_IMAGE_EXPORT_DIRECTORY*) ImageDirectoryEntryToData(LoadedImage.MappedAddress, false, IMAGE_DIRECTORY_ENTRY_EXPORT, &cDirSize);
		if (ImageExportDirectory != NULL) {
			DWORD* dNameRVAs = (DWORD*)ImageRvaToVa(LoadedImage.FileHeader, LoadedImage.MappedAddress, ImageExportDirectory->AddressOfNames, NULL);
			DWORD* dFunRVAs = (DWORD*)ImageRvaToVa(LoadedImage.FileHeader, LoadedImage.MappedAddress, ImageExportDirectory->AddressOfFunctions, NULL);
			for (size_t i = 0; i < ImageExportDirectory->NumberOfNames; i++) {
				const char* cname = (const char*)ImageRvaToVa(LoadedImage.FileHeader, LoadedImage.MappedAddress, dNameRVAs[i], NULL);
				char* target = (char*)ImageRvaToVa(LoadedImage.FileHeader, LoadedImage.MappedAddress, dFunRVAs[i], NULL);
				char* base = (char*)LoadedImage.MappedAddress;
				char* off = (char*)(LoadedImage.Sections->VirtualAddress - LoadedImage.Sections->PointerToRawData);
				ProcessModuleExportedFunction fun(cname, (void*)(target - base + off));
				cb(instance, &fun);
			}
		} else {
			LOG_ERROR("Call to ImageDirectoryEntryToData failed: %d", GetLastError());
			UnMapAndLoad(&LoadedImage);
			return false;
		}
		UnMapAndLoad(&LoadedImage);
	} else {
		LOG_ERROR("Call to MapAndLoad failed: %d", GetLastError());
		return false;
	}
	return true;
}

static PID FindProcessId(const char* processName) {
	HANDLE h = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (h != INVALID_HANDLE_VALUE) {
		PROCESSENTRY32 pEntry;
		pEntry.dwSize = sizeof(pEntry);
		if (!Process32First(h, &pEntry)) { 
			LOG_ERROR("Call to Process32First failed: %d", GetLastError());
			CloseHandle(h);
			return 0;
		} else {
			wchar_t processNameW[MAX_PATH];
			size_t conv = 0;
			mbstowcs_s(&conv, processNameW, processName, MAX_PATH);
			do {
				WCHAR* pName = pEntry.szExeFile;
				if (!lstrcmpW(pName, processNameW)) {
					CloseHandle(h);
					return pEntry.th32ProcessID;
				}
			} while (Process32Next(h, &pEntry));
			CloseHandle(h);
		}
	} else {
		LOG_ERROR("Call to CreateToolhelp32Snapshot failed: %d", GetLastError());
	}
	return 0;
}

Process::Process(const char* name) {
	static_assert(sizeof(buffer) >= sizeof(struct ProcessData), "Buffer too small");
	struct ProcessData* data = reinterpret_cast<struct ProcessData*>(this->buffer);
	memset(data, 0, sizeof(struct ProcessData));

	//data->threads = new(data->threadBuffer)std::map<int, HANDLE>();
	data->threads = new std::map<int, HANDLE>();
	data->threadBases = new std::map<int, THREAD_BASE>();

	data->pid = FindProcessId(name);
	if (!data->pid) {
		LOG_ERROR("No such process: %s", name);
		return;
	}

	/*
	DWORD flags = TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY;
	HANDLE htoken = NULL;
	if (!OpenProcessToken(GetCurrentProcess(), flags, &htoken)) {
		LOG_ERROR("Call to OpenProcessToken failed: %d", GetLastError());
		return;
	}
	LUID id;
	if (!LookupPrivilegeValue(NULL, L"SeDebugPrivilege", &id)) {
		LOG_ERROR("Call to LookupPrivilegeValue failed: %d", GetLastError());
		CloseHandle(htoken);
		return;
	}
	
	TOKEN_PRIVILEGES tp;
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = id;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	if (!AdjustTokenPrivileges(htoken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
		LOG_ERROR("Call to AdjustTokenPrivileges failed: %d", GetLastError());
		CloseHandle(htoken);
		return;
	}
	
	CloseHandle(htoken);
	*/

	data->procHandle = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION | PROCESS_SET_INFORMATION, true, data->pid);
	if (data->procHandle == NULL) {
		LOG_ERROR("Failed to open process: %d", GetLastError());
		return;
	}

	valid = true;
}

Process::~Process() {
	struct ProcessData* data = reinterpret_cast<struct ProcessData*>(this->buffer);

	if (data->attached) {
		this->Detach();
	}

	if (data->procHandle) {
		CloseHandle(data->procHandle);
	}

	if (data->threads) {
		delete data->threads;
		data->threads = nullptr;
	}
	
	if (data->threadBases) {
		delete data->threadBases;
		data->threadBases = nullptr;
	}

	memset(data, 0, sizeof(struct ProcessData));
}

bool Process::IsValid() {
	return valid;
}

bool Process::ReadMem(void* ptr, void* buffer, size_t size) {
	struct ProcessData* data = reinterpret_cast<struct ProcessData*>(this->buffer);
	SIZE_T read = 0;
	if (!ReadProcessMemory(data->procHandle, ptr, buffer, size, &read)) {
		if (errorMessageInhibitors == 0) {
			LOG_ERROR("Call to ReadProcessMemory failed: %d", GetLastError());
		}
		return false;
	}
	return read == size;
}

bool Process::WriteMem(void* ptr, void* buffer, size_t size) {
	struct ProcessData* data = reinterpret_cast<struct ProcessData*>(this->buffer);
	SIZE_T written = 0;
	if (!WriteProcessMemory(data->procHandle, ptr, buffer, size, &written)) {
		LOG_ERROR("Call to WriteProcessMemory failed: %d", GetLastError());
		return false;
	}
	return written == size;
}

bool Process::FlushInstructionCache(void* ptr, size_t size) {
	struct ProcessData* data = reinterpret_cast<struct ProcessData*>(this->buffer);
	if (!::FlushInstructionCache(data->procHandle, ptr, size)) {
		LOG_ERROR("Call to FlushInstructionCache failed: %d", GetLastError());
		return false;
	}
	return true;
}

bool Process::Attach() {
	struct ProcessData* data = reinterpret_cast<struct ProcessData*>(this->buffer);
	if (data->attached) {
		return true;
	}

	data->attached = DebugActiveProcess(data->pid);
	if (!data->attached) {
		LOG_ERROR("Call to DebugActiveProcess failed: %d", GetLastError());
	}

	return data->attached;
}

bool Process::Detach() {
	struct ProcessData* data = reinterpret_cast<struct ProcessData*>(this->buffer);
	if (!data->attached) {
		return true;
	}

	BOOL b = DebugActiveProcessStop(data->pid);
	if (!b) {
		LOG_ERROR("Call to DebugActiveProcess failed: %d", GetLastError());
	} else {
		data->attached = false;
	}

	return !data->attached;
}

bool Process::ForAllModules2(void(*cb)(void*, ProcessModule*), void* instance) {
	struct ProcessData* data = reinterpret_cast<struct ProcessData*>(this->buffer);
	const DWORD dummyReq = 1024;
	HMODULE modules[dummyReq];
	memset(modules, 0, sizeof(modules));
	DWORD realReq = 0;
	BOOL b = EnumProcessModules(data->procHandle, modules, dummyReq, &realReq);
	if (!b) {
		LOG_ERROR("Call to EnumProcessModules failed: %d", GetLastError());
		return false;
	}

	char nameBuf[512];

	auto forEachModule = [&](HMODULE mod) {
		if (mod != NULL) {
			if (!GetModuleBaseNameA(data->procHandle, mod, nameBuf, sizeof(nameBuf))) {
				LOG_ERROR("Call to GetModuleBaseNameA failed: %d", GetLastError());
				return false;
			}
			MODULEINFO mi;
			if (!GetModuleInformation(data->procHandle, mod, &mi, sizeof(mi))) {
				LOG_ERROR("Call to GetModuleInformation failed: %d", GetLastError());
				return false;
			}

			ProcessModule pmod(nameBuf, mi.EntryPoint, mi.lpBaseOfDll, mi.SizeOfImage);
			pmod.ptrHmod = mod;
			pmod.procHandle = data->procHandle;
			cb(instance, &pmod);
			return true;
		}
		return false;
	};

	if (realReq <= dummyReq) {
		for (DWORD i = 0; i < realReq; i++) {
			HMODULE mod = modules[i];
			forEachModule(mod);
			break;
		}
		return true;
	} else {
		const DWORD newReq = 2 * realReq;
		HMODULE* tmp = (HMODULE*)malloc(newReq * sizeof(HMODULE));
		if (!tmp) {
			LOG_ERROR("Failed to allocate temporary buffer");
			return false;
		}
		memset(tmp, 0, sizeof(HMODULE) * newReq);
		b = EnumProcessModules(data->procHandle, modules, dummyReq, &realReq);
		if (!b) {
			LOG_ERROR("Call to EnumProcessModules failed: %d", GetLastError());
			return false;
		}
		const DWORD trustedReq = realReq < newReq ? realReq : newReq;
		for (DWORD i = 0; i < trustedReq; i++) {
			HMODULE mod = tmp[i];
			if (!forEachModule(mod)) {
				free(tmp);
				return false;
			}
		}
		free(tmp);
		return true;
	}

	return false;
}

void Process::RegisterBreakpoint(BreakPoint* bp) {
	if (!this->firstBreakPoint) {
		this->firstBreakPoint = bp;
	} else {
		BreakPoint* iter = this->firstBreakPoint;
		while (iter->Next) {
			iter = iter->Next;
		}
		iter->Next = bp;
	}
}

void Process::UnregisterBreakpoint(BreakPoint* bp) {
	if (this->firstBreakPoint == bp) {
		this->firstBreakPoint = bp->Next;
	} else {
		BreakPoint* iter = this->firstBreakPoint;
		while (iter->Next != bp) {
			iter = iter->Next;
		}
		iter->Next = bp->Next;
	}
}

bool Process::WaitForDebugEvent() {
	bool bContinue = true;

	auto ResolveStackBase = [&](int threadID) -> THREAD_BASE {
		HANDLE hThread = GetThreadHandle(threadID);
		
#pragma pack(push, 1)
		struct THREAD_BASIC_INFORMATION {
			NTSTATUS ExitStatus;
			PVOID TebBaseAddress;
			CLIENT_ID ClientId;
			KAFFINITY AffinityMask;
			KPRIORITY Priority;
			KPRIORITY BasePriority;
		};
#pragma pack(pop)

		THREAD_BASIC_INFORMATION basicInfo;
		memset(&basicInfo, 0, sizeof(basicInfo));
		NT_TIB tib;
		memset(&tib, 0, sizeof(tib));
		
		NTSTATUS nStat = NtQueryInformationThread(hThread, static_cast<THREADINFOCLASS>(0), &basicInfo, sizeof(THREAD_BASIC_INFORMATION), NULL);
		if (nStat) {
			LOG_ERROR("Call to WaitForDebugEvent failed: %d", GetLastError());
			return (THREAD_BASE)nullptr;
		}
		if (!ReadMem(basicInfo.TebBaseAddress, &tib, sizeof(NT_TIB))) {
			LOG_ERROR("Reading remote memory failed: %d", GetLastError());
			return (THREAD_BASE)nullptr;
		}
		return (THREAD_BASE)tib.StackBase;
	};

	while (bContinue) {
		DEBUG_EVENT evt;
		if (!::WaitForDebugEvent(&evt, INFINITE)) {
			LOG_ERROR("Call to WaitForDebugEvent failed: %d", GetLastError());
			return false;
		}

		if (evt.dwDebugEventCode == EXCEPTION_DEBUG_EVENT) {
			if (evt.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_BREAKPOINT) {
				bool found = false;
				for (BreakPoint* bp = this->firstBreakPoint; bp; bp = bp->Next) {
					if (bp->destination == evt.u.Exception.ExceptionRecord.ExceptionAddress) {
						lastHit = bp;
						bp->OnHitInternal(&evt);
						found = true;
						break;
					}
				}
				if (found) {
					continue;
				}
			} else if (evt.u.Exception.ExceptionRecord.ExceptionCode == STATUS_SINGLE_STEP) {
				if (lastHit != nullptr) {
					bool eraseLastHit = lastHit->OnPostHitInternal(&evt);
					if (eraseLastHit) {
						lastHit = nullptr;
					}
					return true;
				}
			} else if (evt.u.Exception.ExceptionRecord.ExceptionCode == STATUS_ACCESS_VIOLATION) {
				return false;
			}
			ContinueDebugEvent(evt.dwProcessId, evt.dwThreadId, DBG_CONTINUE);
			return true;
		} else if (evt.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT) {
			struct ProcessData* data = reinterpret_cast<struct ProcessData*>(this->buffer);
			data->threads->emplace(evt.dwThreadId, evt.u.CreateProcessInfo.hThread);
			THREAD_BASE stackBase = ResolveStackBase(evt.dwThreadId);
			data->threadBases->emplace(evt.dwThreadId, stackBase);
		} else if (evt.dwDebugEventCode == CREATE_THREAD_DEBUG_EVENT) {
			struct ProcessData* data = reinterpret_cast<struct ProcessData*>(this->buffer);
			data->threads->emplace(evt.dwThreadId, evt.u.CreateThread.hThread);
			THREAD_BASE stackBase = ResolveStackBase(evt.dwThreadId);
			data->threadBases->emplace(evt.dwThreadId, stackBase);
		} else if (evt.dwDebugEventCode == EXIT_THREAD_DEBUG_EVENT) {
			struct ProcessData* data = reinterpret_cast<struct ProcessData*>(this->buffer);
			data->threads->erase(evt.dwThreadId);
			data->threadBases->erase(evt.dwThreadId);
		}
		ContinueDebugEvent(evt.dwProcessId, evt.dwThreadId, DBG_CONTINUE);

	}

	return false;
}

int Process::GetRemoteStringLength(void* base) {
	int len = 0;
	for (char* cbase = (char*)base; true; cbase = &(cbase[1])) {
		char b = 0;
		if (!ReadMem(cbase, &b, 1)) {
			return -1;
		}
		if (b == '\0') {
			break;
		}
		len++;
	}
	return len;
}

int Process::GetRemoteWStringLength(void* base) {
	int len = 0;
	for (char* cbase = (char*)base; true; cbase = &(cbase[2])) {
		char b = 0;
		if (!ReadMem(cbase, &b, 1)) {
			return -1;
		}
		if (b == '\0') {
			break;
		}
		len++;
	}
	return len;
}

bool Process::ReadRemoteString(void* base, char* target, unsigned int targetLength) {
	int len = GetRemoteStringLength(base);
	if (len >= 0) {
		targetLength--;
		int toCopy = len > (int)targetLength ? (int)targetLength : len;
		if (ReadMem(base, target, toCopy)) {
			target[toCopy] = 0;
			return true;
		}
	}
	return false;
}

bool Process::ReadRemoteWString(void* base, wchar_t* target, unsigned int targetLength){
	int len = GetRemoteWStringLength(base);
	if (len >= 0) {
		targetLength--;
		int toCopy = len > (int)targetLength ? (int)targetLength : len;
		if (ReadMem(base, target, toCopy * sizeof(wchar_t))) {
			target[toCopy] = 0;
			return true;
		}
	}
	return false;
}

void* Process::GetPtrAt(void* base) {
	void* target = nullptr;
	if (ReadMem(base, &target, sizeof(target))) {
		return target;
	}
	return nullptr;
}

void* Process::GetThreadHandle(int threadID) {
	struct ProcessData* data = reinterpret_cast<struct ProcessData*>(this->buffer);
	auto it = data->threads->find(threadID);
	if (it == data->threads->end()) {
		LOG_ERROR("Invalid thread requested: %d", threadID);
		return NULL;
	} else {
		HANDLE h = it->second;
		return h;
	}
}

void* Process::GetStackBase(int threadID) {
	struct ProcessData* data = reinterpret_cast<struct ProcessData*>(this->buffer);
	auto it = data->threadBases->find(threadID);
	if (it == data->threadBases->end()) {
		LOG_ERROR("Invalid thread requested: %d", threadID);
		return NULL;
	} else {
		THREAD_BASE h = it->second;
		return (void*)h;
	}
	return nullptr;
}

BreakPoint::BreakPoint(Process* process, void* destination) {
	this->process = process;
	this->destination = destination;
	process->RegisterBreakpoint(this);
	
	if (!process->ReadMem(destination, &originalByte, 1)) {
		LOG_ERROR("Failed to backup original byte");
		return;
	}
	
	if (!WriteDebugOP()) {
		LOG_ERROR("Failed to replace original byte with a breakpoint");
		return;
	}
	replaced = true;
	valid = true;
}

BreakPoint::~BreakPoint() {
	if (replaced) {
		if (!process->WriteMem(destination, &originalByte, 1)) {
			LOG_ERROR("Failed to restore original byte");
		}
		if (!process->FlushInstructionCache(destination, 1)) {
			LOG_ERROR("Failed to flush instruction cache");
		}
	}
	process->UnregisterBreakpoint(this);
}

bool BreakPoint::IsValid() {
	return valid;
}

Process* BreakPoint::GetProcess() {
	return process;
}

void BreakPoint::OnHitInternal(void* data) {
	DEBUG_EVENT* evt = reinterpret_cast<DEBUG_EVENT*>(data);
	
	HANDLE hThread = process->GetThreadHandle(evt->dwThreadId);
	if (hThread) {
		CONTEXT lcContext;
		lcContext.ContextFlags = CONTEXT_ALL;
		if (!GetThreadContext(hThread, &lcContext)) {
			LOG_ERROR("Call to GetThreadContext failed: %d", GetLastError());
			return;
		}
		lcContext.Eip--;

		lcContext.EFlags |= 0x100;
		if (!SetThreadContext(hThread, &lcContext)) {
			LOG_ERROR("Call to SetThreadContext failed: %d", GetLastError());
			return;
		}
		RestoreOriginalOP();

		ContinueDebugEvent(evt->dwProcessId, evt->dwThreadId, DBG_CONTINUE);
	} else {
		ContinueDebugEvent(evt->dwProcessId, evt->dwThreadId, DBG_CONTINUE);
	}
}

bool BreakPoint::OnPostHitInternal(void* data) {
	DEBUG_EVENT* evt = reinterpret_cast<DEBUG_EVENT*>(data);

	HANDLE hThread = process->GetThreadHandle(evt->dwThreadId);
	if (hThread) {
		CONTEXT lcContext;
		lcContext.ContextFlags = CONTEXT_ALL;
		if (!GetThreadContext(hThread, &lcContext)) {
			LOG_ERROR("Call to GetThreadContext failed: %d", GetLastError());
			return true;
		}
		{
			ThreadData data(&lcContext, process->GetStackBase(evt->dwThreadId));
			data.TRAP() = false;
			OnHit(&data);
		}
		if (!SetThreadContext(hThread, &lcContext)) {
			LOG_ERROR("Call to SetThreadContext failed: %d", GetLastError());
			return true;
		}
		if (!this->WriteDebugOP()) {
			LOG_ERROR("Failed to set breakpoint");
		}
		ContinueDebugEvent(evt->dwProcessId, evt->dwThreadId, DBG_CONTINUE);
	} else {
		ContinueDebugEvent(evt->dwProcessId, evt->dwThreadId, DBG_CONTINUE);
	}
	return true;
}

bool BreakPoint::WriteDebugOP() {
	unsigned char tmp = 0xCC;
	if (!process->WriteMem(destination, &tmp, 1)) {
		LOG_ERROR("Failed to set breakpoint");
		return false;
	}
	if (!process->FlushInstructionCache(destination, 1)) {
		LOG_ERROR("Failed to flush instruction cache");
		return false;
	}
	return true;
}

bool BreakPoint::RestoreOriginalOP() {
	if (!process->WriteMem(destination, &originalByte, 1)) {
		LOG_ERROR("Failed to replace breakpoint with original byte");
		return false;
	}
	if (!process->FlushInstructionCache(destination, 1)) {
		LOG_ERROR("Failed to flush instruction cache");
		return false;
	}
	return true;
}

CommonBreakPoint::CommonBreakPoint(Process* process, void* destination, void(* cb)(void*, ThreadData* threadData, BreakPoint* bp), void* instance) : BreakPoint(process, destination) {
	this->cb = cb;
	this->instance = instance;
}

CommonBreakPoint::~CommonBreakPoint() {

}

void CommonBreakPoint::OnHit(ThreadData* threadData) {
	cb(instance, threadData, this);
}

int& ThreadData::EAX() {
	return EAX_v;
}

int& ThreadData::EBX() {
	return EAX_v;
}

int& ThreadData::ECX() {
	return EBX_v;
}

int& ThreadData::EDX() {
	return EDX_v;
}

int& ThreadData::ESI() {
	return ESI_v;
}

int& ThreadData::EDI() {
	return EDI_v;
}

int& ThreadData::ESP() {
	return ESP_v;
}

int& ThreadData::EBP() {
	return EBP_v;
}

int& ThreadData::EIP() {
	return EIP_v;
}

bool& ThreadData::TRAP() {
	return TRAP_v;
}

void* ThreadData::StackBase() {
	return stack;
}

ThreadData::ThreadData(void* data, void* stack) {
	this->data = data;
	CONTEXT* lcContext = reinterpret_cast<CONTEXT*> (data);
	EAX_v = lcContext->Eax;
	EBX_v = lcContext->Ebx;
	ECX_v = lcContext->Ecx;
	EDX_v = lcContext->Edx;
	
	ESI_v = lcContext->Esi;
	EDI_v = lcContext->Edi;
	
	ESP_v = lcContext->Esp;
	EBP_v = lcContext->Ebp;
	
	EIP_v = lcContext->Eip;

	TRAP_v = (lcContext->EFlags & 0x100) > 0;

	this->stack = stack;
}

ThreadData::~ThreadData() {
	CONTEXT* lcContext = reinterpret_cast<CONTEXT*> (data);
	lcContext->Eax = EAX_v;
	lcContext->Ebx = EBX_v;
	lcContext->Ecx = ECX_v;
	lcContext->Edx = EDX_v;

	lcContext->Esi = ESI_v;
	lcContext->Edi = EDI_v;

	lcContext->Esp = ESP_v;
	lcContext->Ebp = EBP_v;
	
	lcContext->Eip = EIP_v;

	if (TRAP_v) {
		lcContext->EFlags |= 0x100;
	} else {
		lcContext->EFlags &= ~0x100;
	}
}

StepperBreakpoint::StepperBreakpoint(Process* process, void* destination, void(* cb)(void*, ThreadData*, BreakPoint* bp), void* instance)
	: CommonBreakPoint(process, destination, cb, instance) {

}

StepperBreakpoint::~StepperBreakpoint() {

}

bool StepperBreakpoint::OnPostHitInternal(void* data) {
	DEBUG_EVENT* evt = reinterpret_cast<DEBUG_EVENT*>(data);
	bool eraseBreakpoint = true;
	HANDLE hThread = GetProcess()->GetThreadHandle(evt->dwThreadId);
	if (hThread) {
		CONTEXT lcContext;
		lcContext.ContextFlags = CONTEXT_ALL;
		if (!GetThreadContext(hThread, &lcContext)) {
			LOG_ERROR("Call to GetThreadContext failed: %d", GetLastError());
			return eraseBreakpoint;
		}
		{
			ThreadData data(&lcContext, process->GetStackBase(evt->dwThreadId));
			OnHit(&data);
			eraseBreakpoint = !data.TRAP();
		}
		if (!SetThreadContext(hThread, &lcContext)) {
			LOG_ERROR("Call to SetThreadContext failed: %d", GetLastError());
			return eraseBreakpoint;
		}
		if (!this->WriteDebugOP()) {
			LOG_ERROR("Failed to set breakpoint");
		}
		ContinueDebugEvent(evt->dwProcessId, evt->dwThreadId, DBG_CONTINUE);
	} else {
		ContinueDebugEvent(evt->dwProcessId, evt->dwThreadId, DBG_CONTINUE);
	}
	return eraseBreakpoint;
}

ErrorMessageInhibitor::ErrorMessageInhibitor(Process* process) {
	this->process = process;
	process->errorMessageInhibitors++;
}

ErrorMessageInhibitor::~ErrorMessageInhibitor() {
	process->errorMessageInhibitors--;
}