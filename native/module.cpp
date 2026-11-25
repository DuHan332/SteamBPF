#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <sddl.h>
#include <atomic>
#include <array>
#include <cstdio>
#include <cstdlib>
#include <mutex>
#include <set>
#include <sstream>
#include "vendor/minhook/include/MinHook.h"
#include "wire.hpp"

namespace {
std::mutex config_mutex;
bpf::Config config;
std::string failure;
std::atomic<bool> ready{false};
std::atomic<unsigned long long> sent_changes{0}, received_changes{0};
using Frame = bool(*)(void*,const void*,uint32_t,bool);
using Udp = bool(*)(void*,uint8_t,const void*,uint32_t);
using Receive = intptr_t(*)(void*,void*);
using Ownership = bool(*)(void*,uint32_t,void*);
using Subscribed = bool(*)(void*,uint32_t);
Frame frame_original=nullptr;
Udp udp_original=nullptr;
Receive receive_original=nullptr;
Ownership ownership_original=nullptr;
Subscribed subscribed_original=nullptr;
bpf::Config settings() { std::lock_guard<std::mutex> lock(config_mutex); return config; }

bool accessible(const void* address,size_t length,bool write=false) {
    uintptr_t a=reinterpret_cast<uintptr_t>(address);
    if (!a || length>bpf::max_packet || a+length<a) return false;
    uintptr_t end=a+length;
    while (a<end) {
        MEMORY_BASIC_INFORMATION m{};
        if (!VirtualQuery(reinterpret_cast<void*>(a),&m,sizeof(m)) || m.State!=MEM_COMMIT ||
            (m.Protect&(PAGE_GUARD|PAGE_NOACCESS))) return false;
        DWORD p=m.Protect&255;
        if (p!=PAGE_READONLY && p!=PAGE_READWRITE && p!=PAGE_WRITECOPY &&
            p!=PAGE_EXECUTE_READ && p!=PAGE_EXECUTE_READWRITE && p!=PAGE_EXECUTE_WRITECOPY) return false;
        if (write && p!=PAGE_READWRITE && p!=PAGE_WRITECOPY && p!=PAGE_EXECUTE_READWRITE && p!=PAGE_EXECUTE_WRITECOPY) return false;
        uintptr_t next=reinterpret_cast<uintptr_t>(m.BaseAddress)+m.RegionSize;
        if (next<=a) return false;
        a=next;
    }
    return true;
}
bool frame_hook(void* self,const void* data,uint32_t n,bool flag) {
    const void* selected=data; uint32_t length=n;
    try {
        // Retain replacement storage after the call, as the send path may queue it.
        thread_local std::array<bpf::Bytes,8> ring;
        thread_local unsigned cursor=0;
        auto& rewritten=ring[(cursor++)%ring.size()];
        if (accessible(data,n) && bpf::rewrite(static_cast<const uint8_t*>(data),n,false,settings(),rewritten)) {
            ++sent_changes;
            selected=rewritten.data(); length=uint32_t(rewritten.size());
        }
    } catch (...) {}
    return frame_original(self,selected,length,flag);
}
bool udp_hook(void* self,uint8_t type,const void* data,uint32_t n) {
    const void* selected=data; uint32_t length=n;
    try {
        thread_local std::array<bpf::Bytes,8> ring;
        thread_local unsigned cursor=0;
        auto& rewritten=ring[(cursor++)%ring.size()];
        if (type==2 && accessible(data,n) && bpf::rewrite(static_cast<const uint8_t*>(data),n,false,settings(),rewritten)) {
            ++sent_changes;
            selected=rewritten.data(); length=uint32_t(rewritten.size());
        }
    } catch (...) {}
    return udp_original(self,type,selected,length);
}
bool ownership_hook(void* self,uint32_t app,void* result) {
    bool answer=ownership_original(self,app,result);
    // This structure layout is supported only with the exact profiled signature.
    if (settings().protection && accessible(result,0x36,true)) {
        auto p=static_cast<uint8_t*>(result); uint32_t copies=0;
        std::memcpy(&copies,p+0x14,4);
        if ((p[0x35] || p[0x31]) && copies>=1 && !p[0x25]) {
            p[0x2b]=p[0x2c]=p[0x31]=0; p[0x24]=1;
            uint32_t kind=4; std::memcpy(p+4,&kind,4); answer=true;
        }
    }
    return answer;
}
bool subscribed_hook(void* self,uint32_t app) {
    if (app && settings().protection) return false;
    return subscribed_original(self,app);
}
intptr_t receive_hook(void* self,void* object) {
    // The sample probes these aligned packet views. Here only a unique, fully
    // readable protobuf view is accepted, and the object is restored afterwards.
    struct Restore {
        uint8_t* p=nullptr; const uint8_t* data=nullptr; uint32_t size=0;
        ~Restore() { if (p) { std::memcpy(p,&data,8); std::memcpy(p+8,&size,4); } }
    } restore;
    bpf::Bytes rewritten;
    try {
        size_t hit=0; unsigned matches=0; const uint8_t* data=nullptr; uint32_t n=0;
        if (accessible(object,64,true)) for (size_t off: {8u,16u,24u,32u,40u}) {
            const uint8_t* candidate=nullptr; uint32_t size=0;
            std::memcpy(&candidate,static_cast<uint8_t*>(object)+off,8);
            std::memcpy(&size,static_cast<uint8_t*>(object)+off+8,4);
            bpf::Packet view{};
            if (size>=8 && accessible(candidate,size) && bpf::packet(candidate,size,view)) {
                ++matches; hit=off; data=candidate; n=size;
            }
        }
        if (matches==1 && bpf::rewrite(data,n,true,settings(),rewritten)) {
            restore.p=static_cast<uint8_t*>(object)+hit; restore.data=data; restore.size=n;
            const uint8_t* replacement=rewritten.data(); uint32_t length=uint32_t(rewritten.size());
            std::memcpy(restore.p,&replacement,8); std::memcpy(restore.p+8,&length,4);
            ++received_changes;
        }
    } catch (...) {}
    return receive_original(self,object);
}

struct Range { uint8_t* p; size_t n; };
std::vector<Range> code_ranges(HMODULE module) {
    auto base=reinterpret_cast<uint8_t*>(module);
    auto dos=reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    auto nt=reinterpret_cast<IMAGE_NT_HEADERS64*>(base+dos->e_lfanew);
    std::vector<Range> out;
    auto section=IMAGE_FIRST_SECTION(nt);
    for (unsigned i=0;i<nt->FileHeader.NumberOfSections;++i)
        if (section[i].Characteristics&IMAGE_SCN_MEM_EXECUTE)
            out.push_back({base+section[i].VirtualAddress,section[i].Misc.VirtualSize});
    return out;
}
void* unique(const std::vector<Range>& ranges,std::initializer_list<const char*> patterns) {
    std::set<uint8_t*> hits;
    for (auto pattern:patterns) {
        std::istringstream in(pattern); std::string token; std::vector<int> bytes;
        while (in>>token) bytes.push_back(token=="?"?-1:int(std::strtoul(token.c_str(),nullptr,16)));
        if (bytes.empty()) continue;
        for (auto range:ranges) if (range.n>=bytes.size()) {
            for (size_t i=0;i<=range.n-bytes.size();++i) {
                size_t j=0;
                for (;j<bytes.size();++j) if (bytes[j]>=0 && range.p[i+j]!=bytes[j]) break;
                if (j==bytes.size()) hits.insert(range.p+i);
            }
        }
    }
    return hits.size()==1?*hits.begin():nullptr;
}
bool install() {
    HMODULE steam=GetModuleHandleW(L"steamclient64.dll");
    if (!steam) { failure="client_not_loaded"; return false; }
    auto ranges=code_ranges(steam);
    void* frame=unique(ranges,{
        "48 8B C4 55 48 8D 68 ? 48 81 EC C0 00 00 00 48 89 70 ? 49 8B F0",
        "48 8B C4 55 48 8D 68 ? 48 81 EC C0 00 00 00 48 89 70 ?"});
    void* udp=unique(ranges,{
        "40 53 55 56 57 41 56 41 57 48 83 EC 38 48 83 79",
        "48 89 6C 24 10 48 89 74 24 18 57 41 56 41 57 48 83 EC 30 48 83 79"});
    void* receive=unique(ranges,{
        "48 8B C4 55 48 8D A8 ? ? ? ? 48 81 EC 10 05 00 00",
        "48 8B C4 55 48 8D A8 E8 FB FF FF",
        "48 8B C4 55 48 8D A8 98 F6 FF FF"});
    void* ownership=unique(ranges,{"48 8B C4 89 50 10 48 89 48 08 55 53"});
    void* subscribed=unique(ranges,{
        "48 83 EC 58 81 64 24 ? ? ? ? ? 4C 8D 44 24 ? 48 8B 49 ? 33 C0 8B 15 ? ? ? ? C6 44 24 ? ? 81 E2 FF FF FF 00 81 64 24 ? ? ? ? ? 88 44 24 ? 81 64 24 ? ? ? ? ? 80 3D ? ? ? ? ? 48 89 44 24 ? 0F 44 15 ? ? ? ?",
        "48 83 EC 58 81 64 24 ? ? ? ? ? 33 C0 44 0F B6 05 ? ? ? ? 48 8B 49 ? 41 80 E0 03 48 89 44 24 ? 48 89 44 24 ? 48 89 44 24 ? 48 89 44 24 ? C6 44 24 ? ? 81 64 24 ? ? ? ? ?"});
    // Both transport send entry points and receive must be identifiable. Never
    // report a partially installed backend as ready.
    if (!frame || !udp || !receive || !ownership || !subscribed) { failure="signature_mismatch"; return false; }
    if (MH_Initialize()!=MH_OK) { failure="hook_init_failed"; return false; }
    if (MH_CreateHook(frame,reinterpret_cast<void*>(frame_hook),reinterpret_cast<void**>(&frame_original))!=MH_OK ||
        MH_CreateHook(udp,reinterpret_cast<void*>(udp_hook),reinterpret_cast<void**>(&udp_original))!=MH_OK ||
        MH_CreateHook(receive,reinterpret_cast<void*>(receive_hook),reinterpret_cast<void**>(&receive_original))!=MH_OK ||
        MH_CreateHook(ownership,reinterpret_cast<void*>(ownership_hook),reinterpret_cast<void**>(&ownership_original))!=MH_OK ||
        MH_CreateHook(subscribed,reinterpret_cast<void*>(subscribed_hook),reinterpret_cast<void**>(&subscribed_original))!=MH_OK) {
        MH_Uninitialize(); failure="hook_create_failed"; return false;
    }
    if (MH_EnableHook(MH_ALL_HOOKS)!=MH_OK) {
        MH_DisableHook(MH_ALL_HOOKS); MH_Uninitialize(); failure="hook_enable_failed"; return false;
    }
    return true;
}
std::string status() {
    auto cfg=settings();
    std::ostringstream s;
    s<<"OK version=2 pid="<<GetCurrentProcessId()<<" ready="<<ready.load()
     <<" protection="<<cfg.protection<<" silent="<<cfg.silent
     <<" sent="<<sent_changes.load()<<" received="<<received_changes.load();
    if (!failure.empty()) s<<" error="<<failure;
    return s.str();
}
std::string command(std::string value) {
    while (!value.empty() && (value.back()=='\n'||value.back()=='\r')) value.pop_back();
    if (value=="PING" || value=="GET_STATUS") return status();
    if (!ready.load()) return "ERR "+failure;
    unsigned protection,silent; int end=0;
    if (std::sscanf(value.c_str(),"CONFIG protection=%u silent=%u%n",&protection,&silent,&end)!=2 ||
        end!=int(value.size()) || protection>1 || silent>1) return "ERR invalid_config";
    { std::lock_guard<std::mutex> lock(config_mutex); config={bool(protection),bool(silent)}; }
    return status();
}
DWORD WINAPI worker(void*) {
    try { ready=install(); } catch (...) { failure="initialization_failed"; }
    // Restrict control to the process user, SYSTEM, and administrators.
    HANDLE token=nullptr; DWORD needed=0; PSECURITY_DESCRIPTOR descriptor=nullptr;
    if (!OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&token)) return 1;
    GetTokenInformation(token,TokenUser,nullptr,0,&needed);
    std::vector<uint8_t> storage(needed);
    if (!GetTokenInformation(token,TokenUser,storage.data(),needed,&needed)) { CloseHandle(token); return 1; }
    CloseHandle(token); LPWSTR sid=nullptr;
    if (!ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER*>(storage.data())->User.Sid,&sid)) return 1;
    std::wstring acl=L"D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;"; acl+=sid; acl+=L")"; LocalFree(sid);
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(acl.c_str(),SDDL_REVISION_1,&descriptor,nullptr)) return 1;
    SECURITY_ATTRIBUTES security{sizeof(security),descriptor,FALSE};
    wchar_t name[100]; std::swprintf(name,100,L"\\\\.\\pipe\\SteamBPF.%lu",GetCurrentProcessId());
    for (;;) {
        HANDLE pipe=CreateNamedPipeW(name,PIPE_ACCESS_DUPLEX|FILE_FLAG_FIRST_PIPE_INSTANCE,
            PIPE_TYPE_MESSAGE|PIPE_READMODE_MESSAGE|PIPE_WAIT|PIPE_REJECT_REMOTE_CLIENTS,1,2048,2048,2000,&security);
        if (pipe==INVALID_HANDLE_VALUE) break;
        if (ConnectNamedPipe(pipe,nullptr) || GetLastError()==ERROR_PIPE_CONNECTED) {
            char buffer[256]; DWORD count=0;
            if (ReadFile(pipe,buffer,sizeof(buffer),&count,nullptr) && count && count<sizeof(buffer)) {
                try {
                    auto response=command(std::string(buffer,count));
                    DWORD written; WriteFile(pipe,response.data(),DWORD(response.size()),&written,nullptr);
                    FlushFileBuffers(pipe);
                } catch (...) {}
            }
            DisconnectNamedPipe(pipe);
        }
        CloseHandle(pipe);
    }
    LocalFree(descriptor); return 0;
}
}
BOOL WINAPI DllMain(HINSTANCE module,DWORD reason,LPVOID) {
    if (reason==DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(module);
        HMODULE pinned;
        GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS|GET_MODULE_HANDLE_EX_FLAG_PIN,
            reinterpret_cast<LPCWSTR>(module),&pinned);
        HANDLE thread=CreateThread(nullptr,0,worker,nullptr,0,nullptr);
        if (!thread) return FALSE;
        CloseHandle(thread);
    }
    return TRUE;
}
