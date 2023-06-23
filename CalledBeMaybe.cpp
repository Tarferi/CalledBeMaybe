#include "src/Process.h"
#include <string>
#include <map>

struct {
    char* SCMDBase;
    char* GetArchiveHandleBase;

    char* Kernel32Base;
    char* VirtualAlloc;
    char* VirtualFree;

    char* HeapAlloc;
    char* HeapFree;

} Globals;

void RunPrintSaveFiles(Process* scmd, void* SCMDBase) {

    auto OnSaveBegin = [](void* instance, ThreadData* n, BreakPoint* breakpoint) {
        Process* scmd = breakpoint->GetProcess();
        void* ptrWName = scmd->GetPtrAt(((char*)n->ESP()) + 0xC);
        if (ptrWName) {
            wchar_t fileName[1024];
            if (scmd->ReadRemoteWString(ptrWName, fileName, sizeof(fileName) / sizeof(fileName[0]))) {
                printf("Saving file to: %S\n", fileName);
            }
        }
    };

    char* saveFun = (char*)SCMDBase + 0x27910;

    CommonBreakPoint bp(scmd, saveFun, OnSaveBegin, nullptr);
    if (!bp.IsValid()) {
        LOG_ERROR("Failed to register breakpoint");
        return;
    }

    while (scmd->WaitForDebugEvent()) {
        continue;
    }
}

using FoundFun = void(*)();
using ProcessRegisterFun = void(*)(int&, char*, const char*, ThreadData*, Process*, FoundFun);

void SearchRegisterPtrVER(int& steps, char* reg, const char* name, ThreadData* n, Process* scmd, FoundFun foundCB) {
    // Will search 1024 bytes of all registers for "VER " and " REV"
    if (n->TRAP()) {
        char* regP = (char*)reg;

        int stackDepth = 1024;
        for (int i = -stackDepth; i < stackDepth; i++) {
            void* ptrWName = scmd->GetPtrAt(regP + (i));
            char tmp[4];
            if (scmd->ReadMem(ptrWName, &tmp, sizeof(tmp))) {
                if (!memcmp("VER ", tmp, 4) || !memcmp(" REV", tmp, 4)) {
                    printf("Found at step: %d, at 0x%p (%s + %d)\n", steps, (void*)n->EIP(), name, i);
                    n->TRAP() = false;
                    steps = -2;
                    foundCB();
                }
            }
        }
    }
}

void SearchRegisterPtrStareditScenarioCHK(int& steps, char* reg, const char* name, ThreadData* n, Process* scmd, FoundFun foundCB) {
    // Will search 1024 bytes of all registers for "staredit\\scenario.chk"
    if (n->TRAP()) {
        char* regP = (char*)reg;

        int stackDepth = 32;
        for (int i = -stackDepth; i < stackDepth; i++) {
            void* ptrWName = scmd->GetPtrAt(regP + (i));
            char fileName[32];
            if (ptrWName) {
                if (scmd->ReadRemoteString(ptrWName, fileName, sizeof(fileName))) {
                    if (!strcmp(fileName, "staredit\\scenario.chk")) {
                        printf("Found at step: %d, at 0x%p (%s + %d)\n", steps, (void*)n->EIP(), name, i);
                        n->TRAP() = false;
                        steps = -2;
                        foundCB();
                    }
                }
                wchar_t fileName[32];
                if (scmd->ReadRemoteWString(ptrWName, fileName, sizeof(fileName) / sizeof(fileName[0]))) {
                    if (!wcscmp(fileName, L"staredit\\scenario.chk")) {
                        printf("Found at step: %d, at 0x%p (%s + %d)\n", steps, (void*)n->EIP(), name, i);
                        n->TRAP() = false;
                        steps = -2;
                        foundCB();
                    }
                }
            }
        }
    }
}

void ProcessRegisters(int& steps, ThreadData* n, BreakPoint* breakpoint, ProcessRegisterFun processor, FoundFun foundCB) {
    Process* scmd = breakpoint->GetProcess();
    processor(steps, (char*)n->ESP(), "ESP", n, scmd, foundCB);
    processor(steps, (char*)n->EBP(), "EBP", n, scmd, foundCB);
    processor(steps, (char*)n->EAX(), "EAX", n, scmd, foundCB);
    processor(steps, (char*)n->EBX(), "EBX", n, scmd, foundCB);
    processor(steps, (char*)n->ECX(), "ECX", n, scmd, foundCB);
    processor(steps, (char*)n->EDX(), "EDX", n, scmd, foundCB);
    processor(steps, (char*)n->EDI(), "EDI", n, scmd, foundCB);
    processor(steps, (char*)n->ESI(), "ESI", n, scmd, foundCB);

    printf("Steps: %d\n", steps);
}

void RunSaveStepping(Process* scmd, void* SCMDBase, ProcessRegisterFun fun, FoundFun foundCB) {

    char* saveFun = (char*)SCMDBase + 0x11E1B0;

    int steps = 0;

    struct tmp {
        ProcessRegisterFun* fun;
        int* steps;
        FoundFun foundCB;
    } tmpI{ &fun, &steps, foundCB };

    auto OnBreakpoint = [](void* instance, ThreadData* n, BreakPoint* breakpoint) {
        struct tmp* tmpI = reinterpret_cast<struct tmp*>(instance);
        int& steps = *(tmpI->steps);
        ProcessRegisterFun& fun = *(tmpI->fun);
        Process* scmd = breakpoint->GetProcess();
        ErrorMessageInhibitor inh(scmd);
        n->TRAP() = true;
        ProcessRegisters(steps, n, breakpoint, fun, tmpI->foundCB);
        steps++;
    };

    StepperBreakpoint bp(scmd, saveFun, OnBreakpoint, &tmpI);
    if (!bp.IsValid()) {
        LOG_ERROR("Failed to register breakpoint");
        return;
    }
    while (scmd->WaitForDebugEvent()) {
        if (steps < 0) {
            break;
        }
    }
}

void RunDebugAllocations(Process* scmd) {
    char* saveFun = (char*)Globals.SCMDBase + 0x11E1B0;
    
    char* virtualAlloc = (char*)((unsigned int)Globals.Kernel32Base + (unsigned int)Globals.VirtualAlloc);
    char* virtualFree = (char*)((unsigned int)Globals.Kernel32Base + (unsigned int)Globals.VirtualFree);

    std::map<void*, int> alloc;
    struct tmp {
        std::map<void*, int>* alloc;
        int steps;
        char* virtualAlloc;
        char* virtualFree;
        void(*OnBreakpointAlloc)(void*, ThreadData*, BreakPoint*);
        void(*OnBreakpointFree)(void*, ThreadData*, BreakPoint*);
    } tmpI{ &alloc, 0, virtualAlloc, virtualFree };
    
    auto OnBreakpointAlloc = [](void* instance, ThreadData* n, BreakPoint* breakpoint) {
        struct tmp* tmpI = reinterpret_cast<struct tmp*>(instance);
        Process* scmd = breakpoint->GetProcess();

        void* ptrSz = (void*)(n->ESP() + 0xC);
        int allocSz = (int)scmd->GetPtrAt(ptrSz);

        void* ptrRetAddr = (void*)(n->ESP() + 0x0);
        void* retAddr = scmd->GetPtrAt(ptrRetAddr);
        
        void* allocated = (void*)n->EAX();

        if (allocSz) {
            tmpI->alloc->emplace(allocated, allocSz);
            LOG_ERROR("Allocating %d bytes at 0x%p from 0x%p", allocSz, allocated, retAddr);
        }
    };
    
    auto OnBreakpointFree = [](void* instance, ThreadData* n, BreakPoint* breakpoint) {
        struct tmp* tmpI = reinterpret_cast<struct tmp*>(instance);
        Process* scmd = breakpoint->GetProcess();
                
        void* ptrMem = (void*)(n->ESP() + 0xC);
        void* mem = scmd->GetPtrAt(ptrMem);

        void* ptrRetAddr = (void*)(n->ESP() + 0x0);
        void* retAddr = scmd->GetPtrAt(ptrRetAddr);

        if (ptrMem) {
            auto it = tmpI->alloc->find(ptrMem);
            if (it != tmpI->alloc->end()) {
                int allocSz = it->second;
                LOG_ERROR("Freeing %d bytes at 0x%p from 0x%p", allocSz, mem, retAddr);
            } else {
                LOG_ERROR("Freeing some unknown memory");
            }
        }
        
    };

    tmpI.OnBreakpointAlloc = OnBreakpointAlloc;
    tmpI.OnBreakpointFree = OnBreakpointFree;

    auto OnBreakpoint = [](void* instance, ThreadData* n, BreakPoint* breakpoint) {
        struct tmp* tmpI = reinterpret_cast<struct tmp*>(instance);
        char* EIP = (char*)n->EIP();
        tmpI->steps++;
        n->TRAP() = true;
        LOG_ERROR("Steps: %d", tmpI->steps);
        if (EIP == tmpI->virtualAlloc) {
            tmpI->OnBreakpointAlloc(instance, n, breakpoint);
        } else if (EIP == tmpI->virtualFree) {
            tmpI->OnBreakpointFree(instance, n, breakpoint);
        }
    };
    
    // Note: rewriting kernel32.dll is frowned upon
    // CommonBreakPoint bpAlloc(scmd, virtualAlloc, OnBreakpointAlloc, &tmpI);
    // CommonBreakPoint bpFree(scmd, virtualAlloc, OnBreakpointFree, &tmpI);
    // if (!bpAlloc.IsValid() || !bpFree.IsValid()) {
    //     LOG_ERROR("Failed to register breakpoint");
    //     return;
    // }
    // while (scmd->WaitForDebugEvent()) {
    //     continue;
    // }

    StepperBreakpoint bp(scmd, saveFun, OnBreakpoint, &tmpI);
    if (!bp.IsValid()) {
        LOG_ERROR("Failed to register breakpoint");
        return;
    }
    while (scmd->WaitForDebugEvent()) {
        continue;
    }
}

int main() {
    memset(&Globals, 0, sizeof(Globals));
    Process scmd("ScmDraft 2.exe");
    if (!scmd.IsValid()) {
        LOG_ERROR("Failed to open process");
        return 1;
    }
    if (!scmd.Attach()) {
        LOG_ERROR("Failed to attach to process");
    }

    scmd.ForAllModules([&](ProcessModule* module) {
        if (!strcmp(module->GetName(), "ScmDraft 2.exe")) {
            Globals.SCMDBase = (char*)module->GetBaseAddress();
            module->ForAllExportedFunctions([&](ProcessModuleExportedFunction* fun) {
                if (!strcmp(fun->GetName(), "GetArchiveHandle")) {
                    Globals.GetArchiveHandleBase = (char*)fun->GetLocation();
                }
            });
        } else if (!_stricmp(module->GetName(), "kernel32.dll")) {
            Globals.Kernel32Base = (char*)module->GetBaseAddress();
            module->ForAllExportedFunctions([&](ProcessModuleExportedFunction* fun) {
                if (!strcmp(fun->GetName(), "VirtualAlloc")) {
                    Globals.VirtualAlloc = (char*)fun->GetLocation();
                } else if (!strcmp(fun->GetName(), "VirtualFree")) {
                    Globals.VirtualFree = (char*)fun->GetLocation();
                } else if (!strcmp(fun->GetName(), "HeapAlloc")) {
                    Globals.HeapAlloc = (char*)fun->GetLocation();
                }else if (!strcmp(fun->GetName(), "HeapFree")) {
                    Globals.HeapFree = (char*)fun->GetLocation();
                }
            });
        }
    });

    if (!Globals.GetArchiveHandleBase) {
        LOG_ERROR("Failed to locate GetArchiveHandleBase");
        return 1;
    }

    // To print files are they are being saved
    //RunPrintSaveFiles(&scmd, SCMDBase);

    // Callback
    auto cb = []() {
        printf("Found\n");
    };

    // To print registers looking for "VER " and " REV"
    //RunSaveStepping(&scmd, SCMDBase, SearchRegisterPtrVER, cb);
  
    // To print registers looking for "staredit\\scenario.chk"
    //RunSaveStepping(&scmd, SCMDBase, SearchRegisterPtrStareditScenarioCHK, cb);
    
    // To debug allocations
    RunDebugAllocations(&scmd);
  
    return 0;
}
