// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "windows.h"
#include <fstream>
#include <map>
#include <string>
#include <thread>
#include <filesystem>
#include "util.h"
#include "memory_patch.cpp"
#include "reframework/API.hpp"

using namespace std;
using namespace reframework;

void* (*loadFile)(void*, wchar_t*, int) = (void* (*)(void*, wchar_t*, int))0; //MonsterHunterRise.exe+3D536B0
void* (*_loadFile)(void*, wchar_t*, int) = (void* (*)(void*, wchar_t*, int))0; //MonsterHunterRise.exe+3E57D40 
int (*CheckFileInPak)(void*, UINT64) = (int (*)(void*, UINT64))0; //MHRiseSunbreakDemo.exe+3057E80
UINT64(*PathToHash)(wchar_t*) = (ULONG64(*)(wchar_t*))0; //MHRiseSunbreakDemo.exe+3058DF0
void(*_CloseHandle)(HANDLE*) = (void(*)(HANDLE*))0; //143bdcee0
bool(*prePath)(void*, wchar_t*, void*);//MonsterHunterRise.exe + 3D57430
void(*loadPfb)(void* rfb, bool t);//143E63700

//void snow.player.PlayerManager::reqPlayer(void* vmctx, snow.player.PlayerManager* this,snow.player.PlayerRequestEquipsData* equipsData)
void (*reqPlayer)(void* vmctx, void* self, void* equipsData);

void* (*findMasterPlayer)(void* vmctx, void* self);
//System.String * System.Enum::GetName(void *vmctx,System.Type *enumType,System.Object *value)

map<UINT64, string> hashs;
bool bone = false;
map<int, string>enums;
string modelId;
void* get_method(string type, string name)
{
    return API::get()->tdb()->find_method(type, name)->get_function_raw();
}
void init_enum()
{
    if (enums.empty())
    {
        auto type = API::get()->tdb()->find_type("snow.data.DataDef.PlArmorModelId");
        auto fields = type->get_fields();
        for (auto iter = fields.begin(); iter != fields.end(); iter++)
        {
            auto field = *iter;
            if (field->is_static())
            {
                string name = field->get_name();
                int value = field->get_data<int>();
                enums[value] = name;
            }

        }
    }
}
string wideCharToMultiByte(wchar_t* pWCStrKey)
{
    int pSize = WideCharToMultiByte(CP_OEMCP, 0, pWCStrKey, wcslen(pWCStrKey), NULL, 0, NULL, NULL);
    char* pCStrKey = new char[pSize + 1];
    WideCharToMultiByte(CP_OEMCP, 0, pWCStrKey, wcslen(pWCStrKey), pCStrKey, pSize, NULL, NULL);
    pCStrKey[pSize] = '\0';
    string str = string(pCStrKey);
    delete[] pCStrKey;
    return str;
}
void multiByteToWideChar(const string& pKey, wchar_t* pWCStrKey)
{
    const char* pCStrKey = pKey.c_str();
    int pSize = MultiByteToWideChar(CP_OEMCP, 0, pCStrKey, strlen(pCStrKey) + 1, NULL, 0);
    MultiByteToWideChar(CP_OEMCP, 0, pCStrKey, strlen(pCStrKey) + 1, pWCStrKey, pSize);

}

void hook()
{
    MH_Initialize();
    HookLambda(loadFile, [](auto a, auto b, auto c) {
        if (b == nullptr)return original(a, b, c);
        string path = wideCharToMultiByte(b);
        auto f = path.find("_shadow.mesh.2109148288", 0);
        if (f != string::npos)
        {
            auto bone_index = path.find("bone", 0);
            if (bone_index != string::npos && bone)
            {
                string npath = path.replace(bone_index, 4, modelId);
                if (filesystem::exists(npath.c_str()))
                {
                    path = npath;
                    multiByteToWideChar(path, b);
                }
            }
        }
        UINT64 hash = PathToHash(b);
        if (filesystem::exists(path.c_str()))
        {
            hashs[hash] = path;
        }
        return original(a, b, c);
        });
    HookLambda(CheckFileInPak, [](auto a, auto b) { //判断hash是否存在pak中
        int ret = original(a, b);
        if (ret == -1)return ret;
        if (hashs.find(b) != hashs.end())
        {
            if (filesystem::exists(hashs[b]))
            {
                ret = -1;
            }
            else
            {
                hashs.erase(b);
            }
        }
        return ret;
        });

    HookLambda(reqPlayer, [](void* vmctx, void* self, void* equipsData) {
        int* index = offsetPtr<int>(*offsetPtr<void*>(equipsData, 0x10), 0x24);
        bool suit = true;
        for (int i = 0; i < 4; i++)
        {
            int temp = *index++;
            suit = suit && (temp == *index);
        }
        bone = suit;
        if (bone)
        {
            init_enum();
            modelId = enums[*index];
        }
        return original(vmctx, self, equipsData);
        }
    );
    MH_ApplyQueued();
}

bool Aob()
{
    vector<BYTE*> ret;
    ret = aob("40 55 53 41 56 48 8d ac 24 c0 f0 ff ff");
    if (ret.size() != 1)
    {
        return false;
    }
    PathToHash = (ULONG64(*)(wchar_t*))(ret[0]);
    ret = aob("48 89 6C 24 20 41 56 48 83 EC 20 48 83 B9 A8 00 00 00 00"); //48 89 6C 24 20 41 56 48 83 EC 20 48 83 B9 A8 00 00 00 00
    if (ret.size() != 1)
    {
        ret = aob("48 89 6C 24 20 41 56 48 83 EC 20 45 33 C0");
        if (ret.size() != 1)
        {
            return false;
        }
    }
    CheckFileInPak = (int (*)(void*, UINT64))(ret[0]);
    ret = aob("40 53 48 83 EC 20 48 8B D9 E8 ???? 48 8D 05 ???? 48 89 03 33 C0 48 89 83 98 00 00 00 48 89 83 A0 00 00 00 48 89 83 A8 00 00 00 48 8B C3 48 83 C4 20 5B C3");
    if (ret.size() != 1)
    {
        return false;
    }
    loadFile = (void* (*)(void*, wchar_t*, int))(ret[0]);//MonsterHunterRise.exe+3B2AF60 
    ret = aob("40 53 48 83 EC 20 48 8B D9 E8 ? ? ? ? 48 8B 4B 50 48 85 c9 74 0E FF 15 ? ? ? ? 48 C7 43 50 00 00 00 00 48 83 C4 20 5B C3");
    if (ret.size() != 1)
    {
        return false;
    }
    _CloseHandle = (void (*)(HANDLE*))(ret[0]);
    ret = aob("4C 8B DC 49 89 5B 08 55 56 57 41 54 41 55 41 56 41 57 48 83 EC 50 48 8B 42 50 49 8B F0 4C 8B FA 48 89 44 24 40 48 8B D0 41 C6 43 18 00 4D 8D 43 18 48 8B D9 E8");
    if (ret.size() != 1)
    {
        return false;
    }
    reqPlayer = (void (*)(void*, void*, void*))(ret[0]);
    return true;
}
void Init()
{
    while (true)
    {
        if (Aob())
        {
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    }
    hook();
}
bool Load()
{
    thread(Init).detach();
    return true;
}
extern "C" __declspec(dllexport) void reframework_plugin_required_version(REFrameworkPluginVersion * version) {
    version->major = REFRAMEWORK_PLUGIN_VERSION_MAJOR;
    version->minor = REFRAMEWORK_PLUGIN_VERSION_MINOR;
    version->patch = REFRAMEWORK_PLUGIN_VERSION_PATCH;
}

extern "C" __declspec(dllexport) bool reframework_plugin_initialize(const REFrameworkPluginInitializeParam * param) {
    reframework::API::initialize(param);
    return true;
}
BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    if (ul_reason_for_call == DLL_PROCESS_ATTACH)
        return Load();
    return TRUE;
}