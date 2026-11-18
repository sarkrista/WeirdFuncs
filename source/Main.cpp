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
#include "CSprite.h"
#include "CClothes.h"
#include "CModelInfo.h"
#include "CObject.h"
#include "CPools.h"
#include "CClumpModelInfo.h"
#include "extensions/ScriptCommands.h"
#include "CPlayerPed.h"
#include "CMessages.h"
#include "Fx_c.h"
#include <unordered_set>
#include "CPointLights.h"
#include "CCoronas.h"
#include "CVehicleModelInfo.h"
#include "common.h"
#include "CGeneral.h"
#include <map>
#include <set>
#include <cmath>
#include <chrono>

using namespace plugin;

class WeirdFuncs {
public:
	struct LibcxxString {
		union {
			struct {
				uint8_t size_and_flag;
				char data[11];
			} s;
			struct {
				size_t cap;
				size_t size;
				char* data;
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
			if (!str)
				str = "";
			size_t len = strlen(str);

			if (len <= 10) {
				s.size_and_flag = static_cast<uint8_t>(len << 1);
				memcpy(s.data, str, len + 1);
			}
			else {
				size_t allocSize = (len + 16) & ~15;
				char* buf = static_cast<char*>(HeapAlloc(GetProcessHeap(), 0, allocSize));
				if (buf) {
					memcpy(buf, str, len + 1);
					l.cap = allocSize | 1;
					l.size = len;
					l.data = buf;
				}
			}
		}

		~LibcxxString() {
			if ((s.size_and_flag & 1) && l.data) {
				HeapFree(GetProcessHeap(), 0, l.data);
			}
		}
	};

	static constexpr const char* scriptVersion = "v0.3.4";

	typedef void(__cdecl* tHandleChatSubmit)(const LibcxxString& text);
	typedef void(__thiscall* tChatAdd)(void* chatThis, const LibcxxString& text, uint32_t argb);

	static inline tHandleChatSubmit OriginalHandleChatSubmit = nullptr;
	static inline tChatAdd OriginalChatAdd = nullptr;
	static inline void* g_ChatInstance = nullptr;

	// Rare Hermes
	static inline std::map<CVehicle*, std::vector<CObject*>> g_RareHermesLights;
	static inline std::set<CVehicle*> g_RareHermesSet;
	static inline std::set<CVehicle*> g_CheckedVehicles;

	// Distortion
	static inline bool  g_bEnablePeds = false;
	static inline float g_fPedSpeed = 0.013f;
	static inline float g_fPedStrength = 0.15f;

	static inline bool  g_bEnableVehicles = false;
	static inline float g_fVehSpeed = 0.013f;
	static inline float g_fVehStrength = 0.15f;

	// Paintings state
	static inline bool g_PaintModeActive = false;
	static inline int g_TargetColor1 = -1;
	static inline int g_TargetColor2 = -1;
	static inline float g_PaintProgress = 0.0f;
	static inline CVehicle* g_LastPaintedVeh = nullptr;
	static inline unsigned int g_LastSprayTime = 0;

	static inline const std::vector<unsigned short> g_SingSpeechIds = {
		336
	};

	static inline const std::vector<unsigned short> g_TauntSpeechIds = {
		47, 25, 16, 34, 122
	};

	static DWORD WINAPI InitThread(LPVOID) {
		FILE* log = nullptr;
		fopen_s(&log, "weird_log.txt", "w");
		if (log) { fprintf(log, "Works w/ SA:COOP (https://github.com/Karimov-Akbar/sa-coop) %s\n", scriptVersion); fflush(log); }
		if (log) { fprintf(log, "1. DLL loaded. Waiting for coop.asi...\n"); fflush(log); }

		HMODULE hCoop = nullptr;
		for (int i = 0; i < 100; i++) {
			hCoop = GetModuleHandleA("coop.asi");
			if (hCoop)
				break;
			Sleep(100);
		}
		if (log) { fprintf(log, "2. coop.asi handle: 0x%p\n", hCoop); fflush(log); }
		if (!hCoop) {
			if (log)
				fclose(log);
			return 0;
		}
		Sleep(500);

		// TODO: automatically pick pattern depending on coop version to keep compability
		// v0.3.2
		//uintptr_t addrChatSubmit = FindPattern("coop.asi", "\x55\x53\x57\x56\x83\xEC\x48\x8B\x74\x24\x5C", "xxxxxxxxxxx");
		// v0.3.3
		//uintptr_t addrChatSubmit = FindPattern("coop.asi", "\x55\x53\x57\x56\x83\xEC\x50\x8B\x74\x24\x64", "xxxxxxxxxxx");

		uintptr_t addrChatAdd = FindPattern("coop.asi", "\x55\x89\xE5\x53\x57\x56\x83\xE4\xF8\x83\xEC\x28\x89\xCE", "xxxxxxxxxxxxxx");
		uintptr_t addrChatSubmit = FindPattern("coop.asi", "\x55\x53\x57\x56\x83\xEC\x54\x8B\x74\x24\x68", "xxxxxxxxxxx");

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
	// TODO: pipe custom /help instruction to original command
	// TODO: fix chat size to fit all the text in there; make it scrollable probably?
	static void __cdecl HookedHandleChatSubmit(const LibcxxString& text) {
		const char* cmdText = text.c_str();

		// TODO: add animations for drop type commands?
		if (cmdText) {
			if (strcmp(cmdText, "/droparmor") == 0) {
				HandleDropArmorCommand();
				return;
			}

			if (strcmp(cmdText, "/dropgun") == 0 || strncmp(cmdText, "/dropgun ", 9) == 0) {
				const char* args = (strlen(cmdText) > 9) ? (cmdText + 9) : "";
				HandleDropCurrentWeaponCommand(args);
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

			if (strcmp(cmdText, "/sing") == 0 || strncmp(cmdText, "/sing ", 6) == 0) {
				const char* args = (strlen(cmdText) > 6) ? (cmdText + 6) : "";
				HandleSpeechListCommand(args, g_SingSpeechIds);
				return;
			}

			if (strcmp(cmdText, "/taunt") == 0 || strncmp(cmdText, "/taunt ", 7) == 0) {
				const char* args = (strlen(cmdText) > 7) ? (cmdText + 7) : "";
				HandleSpeechListCommand(args, g_TauntSpeechIds);
				return;
			}

			if (strcmp(cmdText, "/whelp") == 0) {
				HandleWeirdHelpCommand();
				return;
			}

			if (strcmp(cmdText, "/distortcars") == 0) {
				g_bEnableVehicles = !g_bEnableVehicles;
				if (g_bEnableVehicles)
					SendLocalChat("Vehicle distortion enabled", 0xFFFFAAAA);
				else
					SendLocalChat("Vehicle distortion disabled", 0xFFFFAAAA);
				return;
			}

			if (strcmp(cmdText, "/distortpeds") == 0) {
				g_bEnablePeds = !g_bEnablePeds;
				if (g_bEnablePeds)
					SendLocalChat("Peds distortion enabled", 0xFFFFAAAA);
				else
					SendLocalChat("Peds distortion disabled", 0xFFFFAAAA);
				return;
			}
		}

		OriginalHandleChatSubmit(text);
	}

	//////////////////////// /droparmor ////////////////////////
	static void HandleDropArmorCommand() {
		CPlayerPed* player = FindPlayerPed();
		if (!player || player->m_nPedFlags.bInVehicle) {
			SendLocalChat("Exit the car to drop armor", 0xFFFFAAAA);
			return;
		}

		if (player->m_fArmour < 99.9f) {
			SendLocalChat("Armor is damaged thus it can't be dropped", 0xFFFFAAAA);
			return;
		}

		CVector pos = player->TransformFromObjectSpace(CVector(0.0f, 2.0f, 0.0f));
		CPickups::GenerateNewOne(pos, 1242, 3, 0, 0, false, nullptr);

		player->m_fArmour = 0.0f;
	}

	//////////////////////// /dropgun <ammo> ////////////////////////
	static void HandleDropCurrentWeaponCommand(const char* argsStr = "") {
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
				SendLocalChat("Ammo amount can't be a negative number", 0xFFFFAAAA);
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

		if (dropAll) {
			player->ClearWeapon(weaponType);

			eWeaponType nextWeapon = WEAPON_UNARMED;
			for (int slot = activeSlot + 1; slot < 13; ++slot) {
				CWeapon& w = player->m_aWeapons[slot];
				if (w.m_eWeaponType != WEAPON_UNARMED && w.m_nTotalAmmo > 0) {
					nextWeapon = w.m_eWeaponType;
					break;
				}
			}

			if (nextWeapon == WEAPON_UNARMED) {
				for (int slot = 1; slot < activeSlot; ++slot) {
					CWeapon& w = player->m_aWeapons[slot];
					if (w.m_eWeaponType != WEAPON_UNARMED && w.m_nTotalAmmo > 0) {
						nextWeapon = w.m_eWeaponType;
						break;
					}
				}
			}

			player->SetCurrentWeapon(nextWeapon);
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
			SendLocalChat("Specify the exact amount of money", 0xFFFFAAAA);
			return;
		}

		int amount = atoi(argsStr);
		if (amount <= 0) {
			SendLocalChat("Money amount can't be a negative number", 0xFFFFAAAA);
			return;
		}

		CPlayerPed* player = FindPlayerPed();
		if (!player || player->m_nPedFlags.bInVehicle) {
			SendLocalChat("Exit the car to drop money", 0xFFFFAAAA);
			return;
		}

		CPlayerInfo& playerInfo = CWorld::Players[CWorld::PlayerInFocus];
		if (playerInfo.m_nMoney < amount) {
			amount = playerInfo.m_nMoney;
		}

		playerInfo.m_nMoney -= amount;

		CVector pos = player->TransformFromObjectSpace(CVector(0.0f, 2.0f, 0.0f));
		CPickups::GenerateNewOne(pos, 1212, 8, static_cast<unsigned int>(amount), 0, false, nullptr);
	}

	//////////////////////// /paint <color1> <color2> ////////////////////////
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
		if (g_PaintModeActive && (!argsStr || strlen(argsStr) == 0)) {
			CancelPaintMode("Painting canceled manually");
			return;
		}

		CPlayerPed* player = FindPlayerPed();
		if (!player)
			return;

		CWeapon& spraySlot = player->m_aWeapons[9];
		if (spraySlot.m_eWeaponType != WEAPON_SPRAYCAN || spraySlot.m_nTotalAmmo < 100) {
			SendLocalChat("Need more spray (at least 100 units) to perform painting", 0xFFFFAAAA);
			return;
		}

		char arg1[16] = { 0 };
		char arg2[16] = { 0 };
		int parsed = argsStr
			? sscanf_s(argsStr, "%15s %15s", arg1, (unsigned)_countof(arg1), arg2, (unsigned)_countof(arg2))
			: 0;

		if (parsed < 1) {
			SendLocalChat("/paint <color1>", 0xFFFFAAAA);
			return;
		}

		int c1 = -1;
		int c2 = -1;

		if (!ParseColorArg(arg1, c1)) {
			SendLocalChat("Only color IDs available are 0-127", 0xFFFFAAAA);
			return;
		}

		if (parsed >= 2 && !ParseColorArg(arg2, c2)) {
			SendLocalChat("Only color IDs available are 0-127", 0xFFFFAAAA);
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

		SendLocalChat("Spray the car", 0xFFFFC864);
	}

	static void ProcessSprayPainting() {
		if (!g_PaintModeActive)
			return;

		CPlayerPed* player = FindPlayerPed();
		if (!player)
			return;

		if (player->m_nPedFlags.bInVehicle) {
			CancelPaintMode("Painting canceled since you are busy right now...");
			return;
		}

		if (CTimer::m_snTimeInMilliseconds - g_LastSprayTime > 10000) {
			CancelPaintMode("Painting canceled, timed out");
			return;
		}

		CWeapon& spraySlot = player->m_aWeapons[9];
		if (spraySlot.m_nTotalAmmo <= 0) {
			CancelPaintMode("Painting canceled, ran out of spray");
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
					int c1 = (g_TargetColor1 >= 0) ? g_TargetColor1 : veh->m_nPrimaryColor;
					int c2 = (g_TargetColor2 >= 0) ? g_TargetColor2 : veh->m_nSecondaryColor;

					Command<Commands::CHANGE_CAR_COLOUR>(veh, c1, c2);

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
		if (!g_PaintModeActive)
			return;

		CPlayerPed* player = FindPlayerPed();
		if (!player)
			return;

		CVector worldPos = player->GetPosition() + CVector(0.0f, 0.0f, 1.1f);
		if (g_LastPaintedVeh) {
			worldPos = g_LastPaintedVeh->GetPosition() + CVector(0.0f, 0.0f, 1.1f);
		}
		else {
			CVector startPos = player->TransformFromObjectSpace(CVector(0.0f, 0.3f, 0.2f));
			CVector endPos = player->TransformFromObjectSpace(CVector(0.0f, 3.0f, 0.0f));
			CColPoint colPoint;
			CEntity* hitEntity = nullptr;
			if (CWorld::ProcessLineOfSight(startPos, endPos, colPoint, hitEntity, false, true, false, false, false, false, false, false)) {
				if (hitEntity && hitEntity->m_nType == ENTITY_TYPE_VEHICLE) {
					worldPos = hitEntity->GetPosition() + CVector(0.0f, 0.0f, 1.1f);
				}
			}
		}

		RwV3d rwWorld = { worldPos.x, worldPos.y, worldPos.z };
		RwV3d screenPos;
		float w, h;

		float drawX = RsGlobal.maximumWidth * 0.5f;
		float drawY = RsGlobal.maximumHeight * 0.80f;
		if (CSprite::CalcScreenCoors(rwWorld, &screenPos, &w, &h, true, true)) {
			drawX = screenPos.x;
			drawY = screenPos.y;
		}

		char prevOutline = CFont::m_nFontOutline;
		char prevOutlineSize = CFont::m_nFontOutlineSize;
		CFont::m_nFontOutline = 1;
		CFont::m_nFontOutlineSize = 1;

		CFont::SetOrientation(ALIGN_CENTER);
		CFont::SetFontStyle(FONT_SUBTITLES);

		CFont::SetDropColor(CRGBA(0, 0, 0, 255));
		CFont::SetBackground(false, false);

		int pct = static_cast<int>(g_PaintProgress);
		if (pct > 100)
			pct = 100;

		char bufProgress[64];
		sprintf_s(bufProgress, "Painting: %d%%", pct);
		CFont::SetScale(0.45f, 0.95f);
		CFont::SetColor(CRGBA(255, 222, 222, 255));
		CFont::PrintString(drawX, drawY, bufProgress);

		char c1Str[16], c2Str[16];
		if (g_TargetColor1 >= 0) sprintf_s(c1Str, "%d", g_TargetColor1); else strcpy_s(c1Str, "Keep");
		if (g_TargetColor2 >= 0) sprintf_s(c2Str, "%d", g_TargetColor2); else strcpy_s(c2Str, "Keep");

		char bufColors[64];
		sprintf_s(bufColors, "Color 1: %s | Color 2: %s", c1Str, c2Str);
		CFont::SetScale(0.36f, 0.78f);
		CFont::SetColor(CRGBA(233, 222, 222, 255));
		CFont::PrintString(drawX, drawY + 22.0f, bufColors);

		CFont::SetScale(0.33f, 0.72f);
		CFont::SetColor(CRGBA(222, 200, 200, 220));
		CFont::PrintString(drawX, drawY + 40.0f, "use '/paint' to cancel");

		CFont::m_nFontOutline = prevOutline;
		CFont::m_nFontOutlineSize = prevOutlineSize;
	}

	//////////////////////// /skin <id> ////////////////////////
	// TODO: warn about skin breaking if try to change clothes or haircut with different from CJ
	// I'll leave this as unique funny one tho because other skins still will act normal on switch
	// and broken one saves for the session :)

	// TODO: /repairskin command?

	static void HandleSkinCommand(const char* argsStr) {
		if (!argsStr || strlen(argsStr) == 0) {
			SendLocalChat("/skin <id>", 0xFFFFAAAA);
			return;
		}

		int skinId = atoi(argsStr);

		if (skinId < 0 || skinId > 311) {
			SendLocalChat("Skin ID is out of range (0-311)", 0xFFFFAAAA);
			return;
		}

		if (!CModelInfo::GetModelInfo(skinId)) {
			SendLocalChat("No model found for this ID", 0xFFFFAAAA);
			return;
		}

		CPlayerPed* player = FindPlayerPed();
		if (!player)
			return;

		if (player->m_nPedFlags.bInVehicle) {
			SendLocalChat("Exit the car to change the skin", 0xFFFFAAAA);
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

	//////////////////////// /sing <id> ////////////////////////
	//////////////////////// /taunt <id> ////////////////////////
	// TODO: remove cooldown? ain't sure it's worth it, crash risks for such command
	// TODO: add separate taunt IDs for driving state
	static void HandleSpeechListCommand(const char* argsStr, const std::vector<unsigned short>& list) {
		CPlayerPed* player = FindPlayerPed();
		if (!player || list.empty())
			return;

		int index = -1;
		if (argsStr && strlen(argsStr) > 0) {
			index = atoi(argsStr);
			// TODO: specify accurate IDs list to provide user rich info
			if (index < 0 || index >= static_cast<int>(list.size())) {
				SendLocalChat("Bad speech ID", 0xFFFFAAAA);
				return;
			}
		}
		else {
			static bool seeded = false;
			if (!seeded) {
				srand(static_cast<unsigned int>(time(nullptr)));
				seeded = true;
			}
			index = rand() % list.size();
		}

		unsigned short speechId = list[index];

		player->Say(speechId, 0, 1.0f, true, true, false);
	}

	//////////////////////// RARE HERMES ////////////////////////
	static CObject* SpawnAndAttachLightPair(CVehicle* vehicle, int modelId, float offsetX, float offsetY, float offsetZ, float scale) {
		if (!vehicle)
			return nullptr;

		int vehHandle = CPools::GetVehicleRef(vehicle);
		if (vehHandle == -1)
			return nullptr;

		int objHandle = 0;
		CVector pos = vehicle->GetPosition();
		Command<Commands::CREATE_OBJECT>(modelId, pos.x, pos.y, pos.z, &objHandle);

		CObject* lightObj = CPools::GetObject(objHandle);
		if (!lightObj)
			return nullptr;

		lightObj->m_bUsesCollision = false;
		lightObj->m_bLightObject = true;

		Command<Commands::SET_OBJECT_SCALE>(objHandle, scale);
		lightObj->UpdateRwFrame();

		Command<Commands::ATTACH_OBJECT_TO_CAR>(
			objHandle, vehHandle,
			offsetX, offsetY, offsetZ,
			0.0f, 0.0f, 0.0f
		);

		return lightObj;
	}

	static void SetupRareHermes(CVehicle* vehicle) {
		// Init & basic tuning
		if (!vehicle || vehicle->m_nModelIndex != 474)
			return;

		CVehicleModelInfo* vehModelInfo = static_cast<CVehicleModelInfo*>(CModelInfo::GetModelInfo(vehicle->m_nModelIndex));
		if (!vehModelInfo || !vehModelInfo->m_pVehicleStruct)
			return;

		g_RareHermesSet.insert(vehicle);

		vehicle->m_nPrimaryColor = 1;
		vehicle->m_nSecondaryColor = 3;
		vehicle->m_vehicleAudio.m_settings.m_nRadioID = RADIO_RADIO_X;

		vehicle->m_nOverrideLights = 1;
		if (vehicle->m_nVehicleSubClass == VEHICLE_AUTOMOBILE) {
			CAutomobile* autoVeh = static_cast<CAutomobile*>(vehicle);
			autoVeh->m_damageManager.SetLightStatus(LIGHT_FRONT_LEFT, 1);
			autoVeh->m_damageManager.SetLightStatus(LIGHT_FRONT_RIGHT, 1);
		}

		const int upgrades[] = { 1078, 1087, 1010 };
		for (int upgId : upgrades) {
			CStreaming::RequestModel(upgId, GAME_REQUIRED);
		}
		const int lightModelId = 1013;
		CStreaming::RequestModel(lightModelId, GAME_REQUIRED);
		CStreaming::LoadAllRequestedModels(false);

		for (int upgId : upgrades) {
			if (CStreaming::ms_aInfoForModel[upgId].m_nLoadState == LOADSTATE_LOADED) {
				vehicle->AddVehicleUpgrade(upgId);
				CStreaming::SetModelIsDeletable(upgId);
			}
		}

		// Custom headlights
		CVector headlightPos = vehModelInfo->m_pVehicleStruct->m_avDummyPos[0];
		if (headlightPos.y == 0.0f) {
			headlightPos = CVector(0.82f, 2.45f, -0.12f);
		}

		float posY = headlightPos.y - 0.10f;
		float posZ = headlightPos.z;

		std::vector<CObject*> objs;
		if (auto* o1 = SpawnAndAttachLightPair(vehicle, lightModelId, 0.0f, posY, posZ, 1.0f)) objs.push_back(o1);
		if (auto* o2 = SpawnAndAttachLightPair(vehicle, lightModelId, -0.26f, posY, posZ, 1.0f)) objs.push_back(o2);
		if (auto* o3 = SpawnAndAttachLightPair(vehicle, lightModelId, 0.26f, posY, posZ, 1.0f)) objs.push_back(o3);

		g_RareHermesLights[vehicle] = objs;
		CStreaming::SetModelIsDeletable(lightModelId);
	}

	static void SetDealerDriver(CVehicle* vehicle) {
		if (!vehicle)
			return;

		CPed* driver = vehicle->m_pDriver;
		if (!driver || driver->IsPlayer() || driver->m_nModelIndex == 87)
			return;

		int vehHandle = CPools::GetVehicleRef(vehicle);
		if (vehHandle == -1)
			return;

		const int pedId = 87;
		CStreaming::RequestModel(pedId, GAME_REQUIRED);
		CStreaming::LoadAllRequestedModels(false);

		if (CStreaming::ms_aInfoForModel[pedId].m_nLoadState == LOADSTATE_LOADED) {
			int oldPedHandle = CPools::GetPedRef(driver);
			if (oldPedHandle != -1) {
				Command<Commands::DELETE_CHAR>(oldPedHandle);
			}

			int newPedHandle = 0;
			Command<Commands::CREATE_CHAR_INSIDE_CAR>(vehHandle, 5, pedId, &newPedHandle);
			CStreaming::SetModelIsDeletable(pedId);
		}
	}

	static void CleanupRareHermes(CVehicle* vehicle) {
		if (!vehicle)
			return;

		auto it = g_RareHermesLights.find(vehicle);
		if (it != g_RareHermesLights.end()) {
			for (CObject* obj : it->second) {
				if (obj && CPools::ms_pObjectPool->IsObjectValid(obj)) {
					int objHandle = CPools::GetObjectRef(obj);
					if (objHandle != -1) {
						Command<Commands::DELETE_OBJECT>(objHandle);
					}
				}
			}
			g_RareHermesLights.erase(it);
		}
		g_RareHermesSet.erase(vehicle);
	}

	//////////////////////// VEHICLE DISTORTION ////////////////////////
	static void CalculateSquashScale(float speed, float strength, uintptr_t offset, float& outScaleXY, float& outScaleZ) {
		static auto s_startTime = std::chrono::high_resolution_clock::now();
		auto now = std::chrono::high_resolution_clock::now();

		double timeMs = std::chrono::duration<double, std::milli>(now - s_startTime).count();

		double safeOffset = static_cast<double>(offset % 10000);
		double phase = (timeMs + safeOffset) * speed;

		float wave = static_cast<float>(std::sin(phase)) * strength;

		outScaleZ = 1.0f + wave;
		if (outScaleZ < 0.1f)
			outScaleZ = 0.1f;

		outScaleXY = 1.0f - wave * 0.5f;
		if (outScaleXY < 0.1f)
			outScaleXY = 0.1f;
	}

	static void ApplyMatrixScale(RwMatrix* matrix, float scaleXY, float scaleZ) {
		if (!matrix)
			return;

		matrix->right.x *= scaleXY;
		matrix->right.y *= scaleXY;
		matrix->right.z *= scaleXY;

		matrix->up.x *= scaleXY;
		matrix->up.y *= scaleXY;
		matrix->up.z *= scaleXY;

		matrix->at.x *= scaleZ;
		matrix->at.y *= scaleZ;
		matrix->at.z *= scaleZ;
	}

	//////////////////////// /whelp ////////////////////////
	static void HandleWeirdHelpCommand() {
		SendLocalChat("<WeirdFuncs Help>", 0xFFFFAAAA);
		SendLocalChat("/droparmor - works with full one only", 0xFFFFAAAA);
		SendLocalChat("/dropgun <ammo> - if not specified, drops fully", 0xFFFFAAAA);
		SendLocalChat("/dropmoney <amount> - drops money", 0xFFFFAAAA);
		SendLocalChat("/skin <id> - sets skin", 0xFFFFAAAA);
		SendLocalChat("/paint <color1> <color2> - use spray can; use '-' to skip first color", 0xFFFFAAAA);
		SendLocalChat("/sing - random song humming", 0xFFFFAAAA);
		SendLocalChat("/taunt - random phrase speaking", 0xFFFFAAAA);
		SendLocalChat("/distortcars - applies funny squashing effect on vehicle models", 0xFFFFAAAA);
		SendLocalChat("/distortpeds - applies funny squashing effect on peds models", 0xFFFFAAAA);
		SendLocalChat("<For SA : COOP v0.3.4>", 0xFFFFAACC);
	}

	WeirdFuncs() {
		CreateThread(nullptr, 0, InitThread, nullptr, 0, nullptr);
		Events::gameProcessEvent += ProcessSprayPainting;
		Events::drawingEvent += RenderPaintProgress;

		Events::reInitGameEvent += []() {
			g_RareHermesSet.clear();
			};

		Events::vehicleSetModelEvent += [](CVehicle* vehicle, int modelId) {
			CleanupRareHermes(vehicle);
			if (modelId == 474) {
				if (rand() % 100 == 0) {
					g_RareHermesSet.insert(vehicle);
				}
			}
			};

		Events::vehicleSetModelEvent += [](CVehicle* vehicle, int modelId) {
			CleanupRareHermes(vehicle);
			if (modelId == 474 && CGeneral::GetRandomNumberInRange(0, 100) == 0) {
				g_RareHermesSet.insert(vehicle);
			}
			};

		Events::gameProcessEvent += []() {
			if (!CPools::ms_pVehiclePool || !CPools::ms_pPedPool)
				return;

			CVehicle* playerVeh = FindPlayerVehicle(-1, false);

			for (auto it = g_RareHermesSet.begin(); it != g_RareHermesSet.end(); ) {
				CVehicle* vehicle = *it;

				if (!vehicle || !CPools::ms_pVehiclePool->IsObjectValid(vehicle)) {
					it = g_RareHermesSet.erase(it);
					continue;
				}

				if (!vehicle->m_pRwClump) {
					++it;
					continue;
				}

				// FIX: to use this snippet for rare Hermes check need to disable random for garage loaded cars first
				//bool hasRareWheels = false;
				//short* upg = vehicle->m_anUpgrades;
				//for (int i = 0; i < 15; ++i) {
				//	if (*(upg + i) == 1078) {
				//		hasRareWheels = true;
				//		break;
				//	}
				//}

				//bool isSavedRare = (vehicle->m_nCreatedBy != 1 &&
				//	vehicle->m_nPrimaryColor == 1 &&
				//	vehicle->m_nSecondaryColor == 3 &&
				//	hasRareWheels);

				//if ((vehicle->m_nCreatedBy != 1 && !isSavedRare) || vehicle == playerVeh) {
				if ((vehicle->m_nCreatedBy != 1) || vehicle == playerVeh) {
					it = g_RareHermesSet.erase(it);
					continue;
				}

				if (vehicle->m_pRwClump && !g_RareHermesLights.count(vehicle)) {
					SetupRareHermes(vehicle);
				}

				if (vehicle->m_pDriver && CPools::ms_pPedPool->IsObjectValid(vehicle->m_pDriver)) {
					if (!vehicle->m_pDriver->IsPlayer() && vehicle->m_pDriver->m_nModelIndex != 87) {
						SetDealerDriver(vehicle);
					}
				}
				++it;
			}
			};

		Events::vehicleDtorEvent += [](CVehicle* vehicle) {
			g_CheckedVehicles.erase(vehicle);
			CleanupRareHermes(vehicle);
			};

		Events::vehicleRenderEvent.before += [](CVehicle* vehicle) {
			if (!g_bEnableVehicles || !vehicle || !vehicle->m_pRwClump)
				return;

			RwFrame* frame = reinterpret_cast<RwFrame*>(vehicle->m_pRwClump->object.parent);
			if (frame) {
				float scaleXY, scaleZ;
				CalculateSquashScale(g_fVehSpeed, g_fVehStrength, reinterpret_cast<uintptr_t>(vehicle), scaleXY, scaleZ);

				RwMatrix* matrix = RwFrameGetMatrix(frame);

				CBaseModelInfo* modelInfo = CModelInfo::GetModelInfo(vehicle->m_nModelIndex);
				float bottomZ = (modelInfo && modelInfo->m_pColModel)
					? modelInfo->m_pColModel->m_boundBox.m_vecMin.z
					: -0.9f;

				float offsetZ = -bottomZ * (scaleZ - 1.0f);

				matrix->pos.x += matrix->at.x * offsetZ;
				matrix->pos.y += matrix->at.y * offsetZ;
				matrix->pos.z += matrix->at.z * offsetZ;

				ApplyMatrixScale(matrix, scaleXY, scaleZ);
				RwFrameUpdateObjects(frame);
			}
			};

		Events::pedRenderEvent.before += [](CPed* ped) {
			if (!g_bEnablePeds || !ped || !ped->m_pRwClump)
				return;

			RpHAnimHierarchy* hierarchy = GetAnimHierarchyFromSkinClump(ped->m_pRwClump);
			if (!hierarchy)
				return;

			RwMatrix* boneMatrices = RpHAnimHierarchyGetMatrixArray(hierarchy);
			if (!boneMatrices || hierarchy->numNodes <= 0)
				return;

			float scaleXY, scaleZ;
			CalculateSquashScale(g_fPedSpeed, g_fPedStrength, reinterpret_cast<uintptr_t>(ped), scaleXY, scaleZ);

			RwV3d pivotPos = boneMatrices[0].pos;

			float minZ = boneMatrices[0].pos.z;
			for (int i = 1; i < hierarchy->numNodes; ++i) {
				if (boneMatrices[i].pos.z < minZ) {
					minZ = boneMatrices[i].pos.z;
				}
			}
			pivotPos.z = minZ - 0.08f;

			for (int i = 0; i < hierarchy->numNodes; ++i) {
				RwV3dNormalize(&boneMatrices[i].right, &boneMatrices[i].right);
				RwV3dNormalize(&boneMatrices[i].up, &boneMatrices[i].up);
				RwV3dNormalize(&boneMatrices[i].at, &boneMatrices[i].at);

				boneMatrices[i].right.x *= scaleXY;
				boneMatrices[i].right.y *= scaleXY;
				boneMatrices[i].right.z *= scaleZ;

				boneMatrices[i].up.x *= scaleXY;
				boneMatrices[i].up.y *= scaleXY;
				boneMatrices[i].up.z *= scaleZ;

				boneMatrices[i].at.x *= scaleXY;
				boneMatrices[i].at.y *= scaleXY;
				boneMatrices[i].at.z *= scaleZ;

				boneMatrices[i].pos.x = pivotPos.x + (boneMatrices[i].pos.x - pivotPos.x) * scaleXY;
				boneMatrices[i].pos.y = pivotPos.y + (boneMatrices[i].pos.y - pivotPos.y) * scaleXY;
				boneMatrices[i].pos.z = pivotPos.z + (boneMatrices[i].pos.z - pivotPos.z) * scaleZ;
			}
			};

		// TODO: sync drivers with their cars (if both distortions are active)
		// TODO: sync light coronas with cars (if cars distortion is active)

		// TODO: display on original chat created?
		//SendLocalChat("<WeirdFuncs>", 0xFFFFAACC);
		//SendLocalChat("Use /whelp to check the list of commands", 0xFFFFAACC);

		// TODO: add 1254 skull head accessory?
	}
} WeirdFuncsPlugin;