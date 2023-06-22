#include "src/Process.h"
#include <string>

void OnSaveBegin(void* instance, ThreadData* n, BreakPoint* scmd) {
    int* steps = reinterpret_cast<int*>(instance);

    Process* p = scmd->GetProcess();
    /*
    void* ptrWName = p->GetPtrAt(((char*)n->ESP()) + 0xC);
    if (ptrWName) {
        wchar_t fileName[1024];
        if (p->ReadRemoteWString(ptrWName, fileName, sizeof(fileName)/sizeof(fileName[0]))) {
            printf("Saving file to: %S\n", fileName);
        }
    }
    */

    n->TRAP() = true;

    auto processRegister = [&](int reg, const char* name) {
        if (n->TRAP()) {
            ErrorMessageInhibitor inh(p);
            char* regP = (char*)reg;

            /*
            if ((int)reg == 189979) {
                printf("Found at step: %d, at 0x%p (%s + %d)\n", *steps, (void*)n->EIP(), name, 0);
                n->TRAP() = false;
                *steps = -2;
            }
            int tmp = 0;
            if (p->ReadMem((void*)reg, &tmp, sizeof(tmp))) {
                if (tmp == 189979) {
                    printf("Found at step: %d, at 0x%p (%s + %d)\n", *steps, (void*)n->EIP(), name, 0);
                    n->TRAP() = false;
                    *steps = -2;
                }
            }
            
            return;
            */

            int stackDepth = 1024;
            for (int i = -stackDepth; i < stackDepth; i++) {

                /*
                void* ptrWName = p->GetPtrAt(regP + (i));
                if ((int)ptrWName == 189968) {
                    
                    printf("Found at step: %d, at 0x%p (%s + %d)\n", *steps, (void*)n->EIP(), name, i);
                    n->TRAP() = false;
                    *steps = -2;
                }
                int tmp = 0;
                if (p->ReadMem(ptrWName, &tmp, sizeof(tmp))) {
                    if (tmp == 189968) {
                        printf("Found at step: %d, at 0x%p (%s + %d)\n", *steps, (void*)n->EIP(), name, i);
                        n->TRAP() = false;
                        *steps = -2;
                    }
                }
                */

                void* ptrWName = p->GetPtrAt(regP + (i));
                char tmp[4];
                if (p->ReadMem(ptrWName, &tmp, sizeof(tmp))) {
                    if (!memcmp("VER ", tmp, 4)) {
                        printf("Found at step: %d, at 0x%p (%s + %d)\n", *steps, (void*)n->EIP(), name, i);
                        n->TRAP() = false;
                        *steps = -2;
                    }
                }
                
                /*
                char tmp[4];
                if (p->ReadMem(ptrWName, tmp, sizeof(tmp))) {
                    if (!memcmp(tmp, "VER ", 4)) {
                        printf("Found at step: %d, at 0x%p (%s + %d)\n", *steps, (void*)n->EIP(), name, i);
                        n->TRAP() = false;
                        *steps = -2;
                    }
                }
                */
            }
        }

        /*
        int stackDepth = 32;
        for (int i = -stackDepth; i < stackDepth; i++) {
            void* ptrWName = p->GetPtrAt(regP + (4 * i));
            char fileName[32];
            if (ptrWName) {
                if (p->ReadRemoteString(ptrWName, fileName, sizeof(fileName))) {
                    if (!strcmp(fileName, "staredit\\scenario.chk")) {
                        printf("Found at step: %d, at 0x%p (%s + %d)\n", *steps, (void*)n->EIP(), name, i);
                        n->TRAP() = false;
                        *steps = -2;
                    }
                }
                wchar_t fileName[32];
                if (p->ReadRemoteWString(ptrWName, fileName, sizeof(fileName) / sizeof(fileName[0]))) {
                    if (!wcscmp(fileName, L"staredit\\scenario.chk")) {
                        printf("Found at step: %d, at 0x%p (%s + %d)\n", *steps, (void*)n->EIP(), name, i);
                        n->TRAP() = false;
                        *steps = -2;
                    }
                }
            }
        }
        */
    };

    processRegister(n->ESP(), "ESP");
    processRegister(n->EBP(), "EBP");
    processRegister(n->EAX(), "EAX");
    processRegister(n->EBX(), "EBX");
    processRegister(n->ECX(), "ECX");
    processRegister(n->EDX(), "EDX");
    processRegister(n->EDX(), "EDI");
    processRegister(n->EDX(), "ESI");

    printf("Steps: %d\n", *steps);
    *steps = (*steps) + 1;
}

bool HijackSave(Process* scmd, char* SCMDBase) {
    //char* testFun = SCMDBase + 0x27910;
    char* testFun = SCMDBase + 0x11E1B0;
    int steps = 0;
    StepperBreakpoint bp(scmd, testFun, OnSaveBegin, &steps);
    if (!bp.IsValid()) {
        LOG_ERROR("Failed to register breakpoint");
        return false;
    }
    while (scmd->WaitForDebugEvent()) {
        if (steps < 0) {
            break;
        }
        continue;
    }
    return true;
}

int main() {
    Process scmd("ScmDraft 2.exe");
    if (!scmd.IsValid()) {
        LOG_ERROR("Failed to open process");
        return 1;
    }
    if (!scmd.Attach()) {
        LOG_ERROR("Failed to attach to process");
    }

    char* SCMDBase = nullptr;
    char* GetArchiveHandleBase = nullptr;

    scmd.ForAllModules([&](ProcessModule* module) {
        if (!strcmp(module->GetName(), "ScmDraft 2.exe")) {
            SCMDBase = (char*)module->GetBaseAddress();
            module->ForAllExportedFunctions([&](ProcessModuleExportedFunction* fun) {
                if (!strcmp(fun->GetName(), "GetArchiveHandle")) {
                    GetArchiveHandleBase = (char*)fun->GetLocation();
                }
            });
        }
    });

    if (!GetArchiveHandleBase) {
        LOG_ERROR("Failed to locate GetArchiveHandleBase");
        return 1;
    }

    while (HijackSave(&scmd, SCMDBase)) {
        continue;
    }
   
    return 0;
}
