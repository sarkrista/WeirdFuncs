#include <windows.h>
#include <vector>
#include <string>
#include <cstring>
#include <cstdio>
#include "MinHook.h"
#include "plugin.h"
#include "CWorld.h"
#include "CPickups.h"
#include "CWeaponInfo.h"
#include "CVehicle.h"
#include "CPad.h"
#include "CTimer.h"
#include "CFont.h"
#include "CStreaming.h"
#include "CClothes.h"
#include "CModelInfo.h"

using namespace plugin;

class WeirdFuncs {
public:
	// Structure std::__1::basic_string (libc++ - 32-bit x86, 12 bytes)

	// FIX: Calling coop::ui::Chat::Add causes crashes/truncation due to MSVC vs. Clang (libc++) 
	// std::string ABI mismatch and a short signature collision (+0x3B90 vs +0xCB0F0). 
	// Need to verify calling convention (__cdecl vs __thiscall) in Ghidra, resolve ui::TheChat(), 
	// and allocate strings via coop.asi's native operator new.

	// For now it truncates my messages to 10 chars
	struct LibcxxString {
		union {
			struct {
				uint8_t size_and_flag;
				char data[11];
			} s;
			struct {
				size_t cap;
				size_t size;
				const char* data;
			} l;
		};

		const char* c_str() const {
			if (s.size_and_flag & 1) {
				return l.data ? l.data : "";
			}

			return s.data;
		}

		LibcxxString(const char* str) {
			memset(this, 0, sizeof(LibcxxString));
			size_t len = strlen(str);
			if (len > 10)
				len = 10;
			s.size_and_flag = static_cast<uint8_t>(len << 1);
			memcpy(s.data, str, len);
			s.data[len] = '\0';
		}
	};

	static constexpr const char* scriptVersion = "v0.3.3";

	typedef void(__cdecl* tHandleChatSubmit)(const LibcxxString& text);
	typedef void(__thiscall* tChatAdd)(void* chatThis, const LibcxxString& text, uint32_t argb);

	static inline tHandleChatSubmit OriginalHandleChatSubmit = nullptr;
	static inline tChatAdd OriginalChatAdd = nullptr;
	static inline void* g_ChatInstance = nullptr;

	// Paintings state
	static inline bool g_PaintModeActive = false;
	static inline int g_TargetColor1 = -1;
	static inline int g_TargetColor2 = -1;
	static inline float g_PaintProgress = 0.0f;
	static inline CVehicle* g_LastPaintedVeh = nullptr;
	static inline unsigned int g_LastSprayTime = 0;

	static DWORD WINAPI InitThread(LPVOID) {
		FILE* log = nullptr;
		fopen_s(&log, "weird_log.txt", "w");
		if (log) { fprintf(log, "Works w/ SA:COOP (https://github.com/Karimov-Akbar/sa-coop) %s\n", scriptVersion); fflush(log); }
		if (log) { fprintf(log, "1. DLL loaded. Waiting for coop.asi...\n"); fflush(log); }

		HMODULE hCoop = nullptr;
		for (int i = 0; i < 100; i++) {
			hCoop = GetModuleHandleA("coop.asi");
			if (hCoop) break;
			Sleep(100);
		}
		if (log) { fprintf(log, "2. coop.asi handle: 0x%p\n", hCoop); fflush(log); }
		if (!hCoop) {
			if (log) fclose(log);
			return 0;
		}
		Sleep(500);

		// TODO: automatically pick pattern depending on coop version to keep compability
		// v0.3.2
		// uintptr_t addrChatSubmit = FindPattern("coop.asi", "\x55\x53\x57\x56\x83\xEC\x48\x8B\x74\x24\x5C", "xxxxxxxxxxx");

		uintptr_t addrChatAdd = FindPattern("coop.asi", "\x55\x89\xE5\x53\x57\x56\x83\xE4\xF8\x83\xEC\x28\x89\xCE", "xxxxxxxxxxxxxx");
		uintptr_t addrChatSubmit = FindPattern("coop.asi", "\x55\x53\x57\x56\x83\xEC\x50\x8B\x74\x24\x64", "xxxxxxxxxxx");

		if (log) {
			fprintf(log, "3. addrChatAdd: 0x%X | addrChatSubmit: 0x%X\n", addrChatAdd, addrChatSubmit);
			fflush(log);
		}
		if (MH_Initialize() == MH_OK) {
			if (addrChatAdd) {
				MH_STATUS s1 = MH_CreateHook((LPVOID)addrChatAdd, &HookedChatAdd, (LPVOID*)&OriginalChatAdd);
				MH_EnableHook((LPVOID)addrChatAdd);
				if (log) { fprintf(log, "4. Hook ChatAdd status: %d\n", s1); fflush(log); }
			}
			if (addrChatSubmit) {
				MH_STATUS s2 = MH_CreateHook((LPVOID)addrChatSubmit, &HookedHandleChatSubmit, (LPVOID*)&OriginalHandleChatSubmit);
				MH_EnableHook((LPVOID)addrChatSubmit);
				if (log) { fprintf(log, "5. Hook ChatSubmit status: %d\n", s2); fflush(log); }
			}
		}

		if (log)
			fclose(log);

		return 0;
	}

	static uintptr_t FindPattern(const char* moduleName, const char* pattern, const char* mask) {
		HMODULE hMod = GetModuleHandleA(moduleName);
		if (!hMod)
			return 0;

		PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hMod;
		PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((uintptr_t)hMod + dos->e_lfanew);
		size_t size = nt->OptionalHeader.SizeOfImage;
		uint8_t* bytes = (uint8_t*)hMod;
		size_t patLen = strlen(mask);

		for (size_t i = 0; i < size - patLen; i++) {
			bool found = true;
			for (size_t j = 0; j < patLen; j++) {
				if (mask[j] != '?' && pattern[j] != (char)bytes[i + j]) {
					found = false;
					break;
				}
			}
			if (found)
				return (uintptr_t)&bytes[i];
		}
		return 0;
	}

	static void SendLocalChat(const char* msg, uint32_t color) {
		if (g_ChatInstance && OriginalChatAdd) {
			LibcxxString str(msg);
			OriginalChatAdd(g_ChatInstance, str, color);
		}
	}
	//////////////////////// COOP.ASI HOOKS ////////////////////////
	static void __fastcall HookedChatAdd(void* chatThis, void* /*edx*/, const LibcxxString& text, uint32_t argb) {
		g_ChatInstance = chatThis;
		OriginalChatAdd(chatThis, text, argb);
	}

	//////////////////////// CUSTOM COMMANDS HANDLING ////////////////////////
	static void __cdecl HookedHandleChatSubmit(const LibcxxString& text) {
		const char* cmdText = text.c_str();

		// TODO: add animations ?
		if (cmdText) {
			if (strcmp(cmdText, "/dropgun") == 0 || strncmp(cmdText, "/dropgun ", 9) == 0) {
				const char* args = (strlen(cmdText) > 9) ? (cmdText + 9) : "";
				DropCurrentWeapon(args);
				return;
			}

			if (strcmp(cmdText, "/dropmoney") == 0 || strncmp(cmdText, "/dropmoney ", 11) == 0) {
				const char* args = (strlen(cmdText) > 11) ? (cmdText + 11) : "";
				HandleDropMoneyCommand(args);
				return;
			}

			if (strcmp(cmdText, "/paint") == 0 || strncmp(cmdText, "/paint ", 7) == 0) {
				const char* args = (strlen(cmdText) > 7) ? (cmdText + 7) : "";
				HandlePaintCommand(args);
				return;
			}

			if (strncmp(cmdText, "/skin ", 6) == 0) {
				HandleSkinCommand(cmdText + 6);
				return;
			}
		}
		OriginalHandleChatSubmit(text);
	}

	//////////////////////// /dropgun <ammo> ////////////////////////
	static void DropCurrentWeapon(const char* argsStr = "") {
		CPlayerPed* player = FindPlayerPed();
		if (!player || player->m_nPedFlags.bInVehicle)
			return;

		int activeSlot = player->m_nActiveWeaponSlot;
		CWeapon& weapon = player->m_aWeapons[activeSlot];
		eWeaponType weaponType = weapon.m_eWeaponType;

		if (weaponType == WEAPON_UNARMED || weapon.m_nTotalAmmo <= 0)
			return;

		unsigned int totalAmmo = weapon.m_nTotalAmmo;
		unsigned int ammoToDrop = totalAmmo;
		bool dropAll = true;

		if (argsStr && strlen(argsStr) > 0) {
			int requestedAmmo = atoi(argsStr);
			if (requestedAmmo <= 0) {
				SendLocalChat("Bad ammo", 0xFFFFAAAA);
				return;
			}

			if (static_cast<unsigned int>(requestedAmmo) < totalAmmo) {
				ammoToDrop = static_cast<unsigned int>(requestedAmmo);
				dropAll = false;
			}
		}

		CWeaponInfo* wInfo = CWeaponInfo::GetWeaponInfo(weaponType, player->GetWeaponSkill(weaponType));
		int modelId = wInfo ? wInfo->m_nModelId1 : -1;

		if (modelId > 0) {
			CVector pos = player->TransformFromObjectSpace(CVector(0.0f, 2.0f, 0.0f));
			CPickups::GenerateNewOne(pos, modelId, 3, ammoToDrop, 0, false, nullptr);
		}

		// TODO: probably better to pick next to dropped weapon instead of setting to fists?
		if (dropAll) {
			player->ClearWeapon(weaponType);
			player->SetCurrentWeapon(WEAPON_UNARMED);
		}
		else {
			weapon.m_nTotalAmmo -= ammoToDrop;
			if (weapon.m_nAmmoInClip > weapon.m_nTotalAmmo) {
				weapon.m_nAmmoInClip = weapon.m_nTotalAmmo;
			}
		}
	}

	//////////////////////// /dropmoney <amount> ////////////////////////
	static void HandleDropMoneyCommand(const char* argsStr) {
		if (!argsStr || strlen(argsStr) == 0) {
			SendLocalChat("Set amount.", 0xFFFFAAAA);
			return;
		}

		int amount = atoi(argsStr);
		if (amount <= 0) {
			SendLocalChat("Bad amount.", 0xFFFFAAAA);
			return;
		}

		CPlayerPed* player = FindPlayerPed();
		if (!player || player->m_nPedFlags.bInVehicle) {
			SendLocalChat("Exit car.", 0xFFFFAAAA);
			return;
		}

		CPlayerInfo& playerInfo = CWorld::Players[CWorld::PlayerInFocus];
		if (playerInfo.m_nMoney < amount) {
			SendLocalChat("No money.", 0xFFFFAAAA);
			return;
		}

		playerInfo.m_nMoney -= amount;

		CVector pos = player->TransformFromObjectSpace(CVector(0.0f, 2.0f, 0.0f));
		CPickups::GenerateNewOne(pos, 1212, 8, static_cast<unsigned int>(amount), 0, false, nullptr);
	}

	//////////////////////// /paint <color1> <color2> ////////////////////////
	// PUBLIC FIX: same color changing
	// PUBLIC FIX: police should not be touched
	// PUBLIC FIX: painting processing bug (should be converting ammo to percentage)
	// PUBLIC FIX: 200 ammo for each color
	static void CancelPaintMode(const char* reasonMsg = nullptr) {
		g_PaintModeActive = false;
		g_PaintProgress = 0.0f;
		g_LastPaintedVeh = nullptr;
		if (reasonMsg) {
			SendLocalChat(reasonMsg, 0xFFFFAAAA);
		}
	}

	static bool ParseColorArg(const char* arg, int& outColor) {
		if (!arg || arg[0] == '\0')
			return false;

		if (strcmp(arg, "-") == 0) {
			outColor = -1;
			return true;
		}

		for (size_t i = 0; arg[i] != '\0'; ++i) {
			if (arg[i] < '0' || arg[i] > '9')
				return false;
		}

		int val = atoi(arg);
		if (val < 0 || val > 127)
			return false;

		outColor = val;
		return true;
	}

	static void HandlePaintCommand(const char* argsStr) {
		if (g_PaintModeActive && (!argsStr || strlen(argsStr) == 0 || strncmp(argsStr, "cancel", 6) == 0)) {
			CancelPaintMode("Canceled.");
			return;
		}

		CPlayerPed* player = FindPlayerPed();
		if (!player)
			return;

		CWeapon& spraySlot = player->m_aWeapons[9];
		if (spraySlot.m_eWeaponType != WEAPON_SPRAYCAN || spraySlot.m_nTotalAmmo < 80) {
			//SendLocalChat("Need more spray", 0xFFFFAAAA);
			SendLocalChat("No spray", 0xFFFFAAAA);
			return;
		}

		char arg1[16] = { 0 };
		char arg2[16] = { 0 };
		int parsed = argsStr
			? sscanf_s(argsStr, "%15s %15s", arg1, (unsigned)_countof(arg1), arg2, (unsigned)_countof(arg2))
			: 0;

		if (parsed < 1) {
			SendLocalChat("/paint c1", 0xFFFFAAAA);
			return;
		}

		int c1 = -1;
		int c2 = -1;

		if (!ParseColorArg(arg1, c1)) {
			SendLocalChat("Color 0-127", 0xFFFFAAAA);
			return;
		}

		if (parsed >= 2 && !ParseColorArg(arg2, c2)) {
			SendLocalChat("Color 0-127", 0xFFFFAAAA);
			return;
		}

		if (c1 == -1 && c2 == -1)
			return;

		g_TargetColor1 = c1;
		g_TargetColor2 = c2;
		g_PaintProgress = 0.0f;
		g_LastPaintedVeh = nullptr;
		g_LastSprayTime = CTimer::m_snTimeInMilliseconds;
		g_PaintModeActive = true;

		SendLocalChat("Spray car.", 0xFFFFC864);
	}

	static void ProcessSprayPainting() {
		if (!g_PaintModeActive)
			return;

		CPlayerPed* player = FindPlayerPed();
		if (!player)
			return;

		if (player->m_nPedFlags.bInVehicle) {
			CancelPaintMode("Canceled.");
			return;
		}

		if (CTimer::m_snTimeInMilliseconds - g_LastSprayTime > 10000) {
			CancelPaintMode("Timed out.");
			return;
		}

		CWeapon& spraySlot = player->m_aWeapons[9];
		if (spraySlot.m_eWeaponType != WEAPON_SPRAYCAN || spraySlot.m_nTotalAmmo <= 0) {
			CancelPaintMode("No spray.");
			return;
		}

		int activeSlot = player->m_nActiveWeaponSlot;
		if (player->m_aWeapons[activeSlot].m_eWeaponType != WEAPON_SPRAYCAN)
			return;

		CPad* pad = CPad::GetPad(0);
		if (!pad || !pad->NewState.ButtonCircle)
			return;

		g_LastSprayTime = CTimer::m_snTimeInMilliseconds;

		CVector startPos = player->TransformFromObjectSpace(CVector(0.0f, 0.3f, 0.2f));
		CVector endPos = player->TransformFromObjectSpace(CVector(0.0f, 3.0f, 0.0f));

		CColPoint colPoint;
		CEntity* hitEntity = nullptr;

		if (CWorld::ProcessLineOfSight(startPos, endPos, colPoint, hitEntity, false, true, false, false, false, false, false, false)) {
			if (hitEntity && hitEntity->m_nType == ENTITY_TYPE_VEHICLE) {
				CVehicle* veh = static_cast<CVehicle*>(hitEntity);

				if (veh->m_vecMoveSpeed.Magnitude() > 0.05f || veh->m_pDriver != nullptr) {
					return;
				}

				if (g_LastPaintedVeh != veh) {
					g_LastPaintedVeh = veh;
					g_PaintProgress = 0.0f;
				}

				float deltaSeconds = CTimer::ms_fTimeStep / 50.0f;
				g_PaintProgress += 25.0f * deltaSeconds;

				if (g_PaintProgress >= 100.0f) {
					if (g_TargetColor1 >= 0) veh->m_nPrimaryColor = static_cast<unsigned char>(g_TargetColor1);
					if (g_TargetColor2 >= 0) veh->m_nSecondaryColor = static_cast<unsigned char>(g_TargetColor2);

					veh->UpdateRwFrame();

					veh->m_nVehicleFlags.bHasBeenOwnedByPlayer = 1;
					veh->m_nAlarmState = 0;

					g_PaintModeActive = false;
					g_PaintProgress = 0.0f;
					g_LastPaintedVeh = nullptr;
				}
			}
		}
	}

	static void RenderPaintProgress() {
		if (!g_PaintModeActive || g_PaintProgress <= 0.0f)
			return;

		char buf[32];
		sprintf_s(buf, "Painting: %d%%", static_cast<int>(g_PaintProgress));

		CFont::SetOrientation(ALIGN_CENTER);
		CFont::SetColor(CRGBA(255, 200, 200, 255));
		CFont::SetDropShadowPosition(1);
		CFont::SetBackground(false, false);
		CFont::SetScale(0.6f, 1.2f);
		CFont::SetFontStyle(FONT_SUBTITLES);
		CFont::PrintString(320.0f, 380.0f, buf);
	}

	//////////////////////// /skin <id> ////////////////////////
	// FIX: warn about skin breaking if try to change clothes or haircut with different from CJ
	// I'll leave this as unique funny one tho because other skins still will act normal on switch
	// and broken one saves for the session :)

	// TODO: /repairskin command ?

	static void HandleSkinCommand(const char* argsStr) {
		if (!argsStr || strlen(argsStr) == 0) {
			SendLocalChat("/skin <id>", 0xFFFFAAAA);
			return;
		}

		int skinId = atoi(argsStr);

		if (skinId < 0 || skinId > 311) {
			SendLocalChat("Bad skin!", 0xFFFFAAAA);
			return;
		}

		if (!CModelInfo::GetModelInfo(skinId)) {
			SendLocalChat("No model!", 0xFFFFAAAA);
			return;
		}

		CPlayerPed* player = FindPlayerPed();
		if (!player)
			return;

		if (player->m_nPedFlags.bInVehicle) {
			SendLocalChat("Exit car!", 0xFFFFAAAA);
			return;
		}

		if (skinId == 0) {
			player->SetModelIndex(0);
			CClothes::RebuildPlayer(player, false);
			return;
		}

		CStreaming::RequestModel(skinId, 2);
		CStreaming::LoadAllRequestedModels(false);

		player->SetModelIndex(skinId);

		CStreaming::SetModelIsDeletable(skinId);
	}

	WeirdFuncs() {
		CreateThread(nullptr, 0, InitThread, nullptr, 0, nullptr);
		Events::gameProcessEvent += ProcessSprayPainting;
		Events::drawingEvent += RenderPaintProgress;
	}
} WeirdFuncsPlugin;
