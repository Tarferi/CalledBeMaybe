#pragma once
#include "common.h"

class BreakPoint;

class ProcessModuleExportedFunction {

	friend class ProcessModule;

public:

	const char* GetName();

	void* GetLocation();

private:

	ProcessModuleExportedFunction(const char* name, void* ptr);

	~ProcessModuleExportedFunction();

	const char* name = nullptr;
	void* ptr = nullptr;

};

class ProcessModule {

	friend class Process;

public:
	
	const char* GetName();

	void* GetEntryPoint();

	void* GetBaseAddress();

	unsigned int GetModuleSize();

	template<typename callable>
	bool ForAllExportedFunctions(callable cb) {
		struct tmp {
			callable* cb;
		} tmpI{ &cb };
		return ForAllExportedFunctions2([](void* inst, ProcessModuleExportedFunction* fun) {
			struct tmp* tmpI = reinterpret_cast<struct tmp*>(inst);
			(*(tmpI->cb))(fun);
		}, &tmpI);
	}

private:

	ProcessModule(const char* name, void* entryPoint, void* baseAddress, unsigned int size);

	~ProcessModule();

	bool ForAllExportedFunctions2(void(*)(void*, ProcessModuleExportedFunction*), void*);

	const char* name = nullptr;
	void* entryPoint = nullptr;

	void* baseAddress = nullptr;
	unsigned int size = 0;

	void* procHandle = nullptr;
	void* ptrHmod = nullptr;
};

class Process {

	friend class BreakPoint;
	friend class StepperBreakpoint;
	friend class ErrorMessageInhibitor;

public:

	Process(const char* name);

	~Process();

	bool ReadMem(void* ptr, void* data, size_t size);

	bool WriteMem(void* ptr, void* data, size_t size);
	
	bool FlushInstructionCache(void* ptr, size_t size);

	bool IsValid();

	bool Attach();

	bool Detach();

	template<typename callable>
	bool ForAllModules(callable cb) {
		struct tmp {
			callable* cb;
		} tmpI{ &cb };
		return ForAllModules2([](void* inst, ProcessModule* module) {
			struct tmp* tmpI = reinterpret_cast<struct tmp*>(inst);
			(*(tmpI->cb))(module);
		}, &tmpI);
	}

	bool WaitForDebugEvent();

	int GetRemoteStringLength(void* base);
	
	int GetRemoteWStringLength(void* base);

	bool ReadRemoteString(void* base, char* target, unsigned int targetLength);
	
	bool ReadRemoteWString(void* base, wchar_t* target, unsigned int targetLength);

	void* GetPtrAt(void* base);

protected:

	// For debugger
	void* GetThreadHandle(int threadID);

	void* GetStackBase(int threadID);


private:

	void RegisterBreakpoint(BreakPoint* bp);

	void UnregisterBreakpoint(BreakPoint* bp);

	bool valid = false;

	char buffer[64];

	bool ForAllModules2(void(*cb)(void*, ProcessModule*), void*);

	BreakPoint* firstBreakPoint = nullptr;
	
	BreakPoint* lastHit = nullptr;

	int errorMessageInhibitors = 0;
};

class ErrorMessageInhibitor {

public:

	ErrorMessageInhibitor(Process* process);

	~ErrorMessageInhibitor();

private:

	Process* process = nullptr;

};

class ThreadData {

	friend class BreakPoint;
	friend class StepperBreakpoint;

public:

	int& EAX();
	int& EBX();
	int& ECX();
	int& EDX();
	
	int& ESI();
	int& EDI();
	int& ESP();
	int& EBP();
	
	int& EIP();

	bool& TRAP();

	void* StackBase();

private:
	
	ThreadData(void* data, void* stack);

	~ThreadData();

private:
	
	void* data = nullptr;

	int EAX_v = 0;
	int EBX_v = 0;
	int ECX_v = 0;
	int EDX_v = 0;

	int ESI_v = 0;
	int EDI_v = 0;
	
	int ESP_v = 0;
	int EBP_v = 0;
	
	int EIP_v = 0;

	bool TRAP_v = false;

	void* stack = nullptr;

};

class BreakPoint {

	friend class Process;
	friend class StepperBreakpoint;

public:

	BreakPoint(Process* process, void* destination);

	virtual ~BreakPoint();

	bool IsValid();

	Process* GetProcess();

protected:

	virtual void OnHit(ThreadData* threadData) = 0;

private:

	void OnHitInternal(void* data);
	
	virtual bool OnPostHitInternal(void* data);

	bool valid = false;

	Process* process = nullptr;

	void* destination = nullptr;
	
	char originalByte = 0;

	bool replaced = false;

	// For Process purposes
	BreakPoint* Next = nullptr;

	bool WriteDebugOP();

	bool RestoreOriginalOP();
};

class CommonBreakPoint : public BreakPoint {

public:
	
	CommonBreakPoint(Process* process, void* destination, void(*)(void*, ThreadData*, BreakPoint* bp), void*);

	virtual ~CommonBreakPoint();

protected:
	
	virtual void OnHit(ThreadData* threadData) override;

private:

	void(*cb)(void*, ThreadData*, BreakPoint* bp) = nullptr;
	
	void* instance = nullptr;

};

class StepperBreakpoint : public CommonBreakPoint {

public:
	
	StepperBreakpoint(Process* process, void* destination, void(*)(void*, ThreadData*, BreakPoint* bp), void*);

	virtual ~StepperBreakpoint();

private:

	virtual bool OnPostHitInternal(void* data) override;

};