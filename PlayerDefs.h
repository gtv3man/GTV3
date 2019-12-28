#pragma once
#include "enet/enet.h"
#include <Windows.h>
#include <vector>
#include "GTV3Queue.h"
#include "GamePacket.h"
#include "ServerDefs.h"
#include <chrono>
#include <experimental/filesystem>
#include <mysql.h>


using namespace std;

#define cloth0 cloth_hair
#define cloth1 cloth_shirt
#define cloth2 cloth_pants
#define cloth3 cloth_feet
#define cloth4 cloth_face
#define cloth5 cloth_hand
#define cloth6 cloth_back
#define cloth7 cloth_mask
#define cloth8 cloth_necklace
#define STR16(x, y) (*(uint16_t*)(&(x)[(y)]))
#define STRINT(x, y) (*(int*)(&(x)[(y)]))
#define Property_Zero 0
#define Property_NoSeed 1
#define Property_Dropless 2
#define Property_Beta 4
#define Property_Mod 8
#define Property_Untradable 16
#define Property_Wrenchable 32
#define Property_MultiFacing 64
#define Property_Permanent 128
#define Property_AutoPickup 256
#define Property_WorldLock 512
#define Property_NoSelf 1024
#define Property_RandomGrow 2048
#define Property_Public 4096



class Player { 
public:	
	static void OnConsoleMessage(ENetPeer* peer, string text);
	static void OnTalkBubble(ENetPeer* peer, int netID, string text, int chatColor, bool isOverlay);
	static void OnAddNotification(ENetPeer* peer, string text, string audiosound, string interfaceimage);
	static void OnStartAcceptLogon(ENetPeer* peer, int itemdathash);
	static void OnRemove(ENetPeer* peer, int netID);
	static void OnSendToServer(ENetPeer* peer, int userID, int token, string ip, int port, string doorId, int lmode); // no need other args, sub servers done&working already... using fake data etc.
	static void SendTileAnimation(ENetPeer* peer, int x, int y, int causedBy, int tile);
	static void PlayAudio(ENetPeer* peer, string audioFile, int delayMS);
	static void showWrong(ENetPeer* peer, string itemFind, string listFull);
	static void OnZoomCamera(ENetPeer* peer, float value1, int value2);
	static void SmoothZoom(ENetPeer* peer);
	static void OnRaceStart(ENetPeer* peer, int netID);
	static void OnRaceEnd(ENetPeer* peer, int netID);
	static void OnSetCurrentWeather(ENetPeer* peer, int weather);
	static void OnPlayPositioned(ENetPeer* peer, string audiofile, int netID, bool broadcastInWorld, ENetPacket* pk);
	static void OnCountdownStart(ENetPeer* peer, int netID, int time, int score);
	static void OnCountdownUpdate(ENetPeer* peer, int netID, int score);
	static void OnCountdownEnd(ENetPeer* peer);
	static void OnStartTrade(ENetPeer* peer, int netID1, int netID2);
	static void OnTextOverlay(ENetPeer* peer, string text);
	static void OnForceTradeEnd(ENetPeer* peer);
	static void OnFailedToEnterWorld(ENetPeer* peer);
	static void OnNameChanged(ENetPeer* peer, int netID, string name);
	static void OnTradeStatus(ENetPeer* peer, int netIDOther, string offerstatus, string offer);
	static void OnDialogRequest(ENetPeer* peer, string args);
	static void OnKilled(ENetPeer* peer, int netID);
	static void OnSetFreezeState(ENetPeer* peer, int state, int netID);
	static void OnSetPos(ENetPeer* peer, int netID, int x, int y);
	static void OnFlagMay2019(ENetPeer* peer, int state, int netID);	
	static void OnBillboardChange(ENetPeer* peer, int netID); //testing billboards
	static void SendTilePickup(ENetPeer* peer, int itemid, int netID, float x, float y, int itemcount, int itemamount);
	static void OnInvis(ENetPeer* peer, int state, int netID);
	static void OnChangeSkin(ENetPeer* peer, int skinColor, int netID);
	static void SetRespawnPos(ENetPeer* peer, int posX, int posY, int netID);
	static void OnSetBux(ENetPeer* peer, int gems, int accountstate);
	static void OnParticleEffect(ENetPeer* peer, int effect, float x, float y, int delay);
	static void SetHasGrowID(ENetPeer* peer, int status, string username, string password);
	static void Ping(ENetPeer* peer);
};

int isSeed(int id) {
	return id % 2 == 1;
}

struct WorldAdministration {
	int bannedAt = 0;
	bool banned = false;
};


struct InventoryItem {
	__int16 itemID;
	__int8 itemCount;
};

struct PlayerInventory {
	vector<InventoryItem> items;
	int inventorySize = 100;
};

struct PlayerInfo {
	vector<string> paid;
	int gems = 0;
	bool isinv = false;
	int droppeditemcount = 0;
	int packetinsec = 0;
	long long int packetsec = 0;
	bool isIn = false;
	bool hasLogon = false;
	int netID;
	int estcapes = 0;
	int lwings = 0;
	int lbots = 0;
	int lkatanas = 0;
	int ldrags = 0;
	int userID = 0;
	string doorID = "";
	bool invalidUser = false;
	int totalKills = 0;
	bool boughtEC = false;
	bool haveGrowId = false;
	string rid = "";
	bool evadeRID = false;
	string sid = "";
	string aid = "";
	string gid = "";
	string vid = "";
	string zf = "";
	string mac = "";
	string platformID = "";
	string gameVersion = "";
	string hash = "";
	string hash2 = "";
	string tankIDName = "";
	string tankIDPass = "";
	bool isNicked = false;
	string requestedName = "";
	string rawName = "";
	string displayName = "";
	string socialName = "";
	string displayNamebackup = "";
	int health = 100;
	int score = 0;
	string country = "";
	int adminLevel = 0;
	string currentWorld = "EXIT";
	bool goesPVP = false;
	int lastSignId = 0;
	int lastSignBg = 0;
	int lastPunchX = 0;
	int lastPunchY = 0;
	string lastHitCoordX = "-1";
	string lastHitCoordY = "-1";
	int lastPVPcoord;
	int lastPVPcoord2;
	int lastPVPcoord3;
	int lastPVPcoord4;
	int lastPVPcoord5;
	int lastPVPcoord6;
	int lastPVPcoord7;
	int createdWorldsSession = 0;
	bool radio = true;
	int x;
	int y;
	int x1;
	int y1;
	bool isRotatedLeft = false;
	bool respawnReq = false;
	bool respawnReqA = false;
	string charIP = "";
	int enetIP = 0;
	bool isUpdating = false;
	bool joinClothesUpdated = false;
	bool taped = false;
	bool dead = false;

	int cloth_hair = 0; // 0
	int cloth_shirt = 0; // 1
	int cloth_pants = 0; // 2
	int cloth_feet = 0; // 3
	int cloth_face = 0; // 4
	int cloth_hand = 0; // 5
	int cloth_back = 0; // 6
	int cloth_mask = 0; // 7
	int cloth_necklace = 0; // 8
	int cloth_ances = 0; // 9

	bool canWalkInBlocks = false; // 1
	bool canDoubleJump = false; // 2
	bool isInvisible = false; // 4
	bool noHands = false; // 8
	bool noEyes = false; // 16
	bool noBody = false; // 32
	bool devilHorns = false; // 64
	bool goldenHalo = false; // 128
	bool isFrozen = false; // 2048
	bool isCursed = false; // 4096
	bool isDuctaped = false; // 8192
	bool haveCigar = false; // 16384
	bool isShining = false; // 32768
	bool isZombie = false; // 65536
	bool isHitByLava = false; // 131072
	bool haveHauntedShadows = false; // 262144
	bool haveGeigerRadiation = false; // 524288
	bool haveReflector = false; // 1048576
	bool isEgged = false; // 2097152
	bool havePineappleFloag = false; // 4194304
	bool haveFlyingPineapple = false; // 8388608
	bool haveSuperSupporterName = false; // 16777216
	bool haveSupperPineapple = false; // 33554432
	bool isGhost = false;

	int smstate = 0;
	int mstate = 0;
	int lastTradeNetID = 0;
	int lastTradeItem = 0;
	int lavaLevel = 0;	



	string lastTradeName = "";
	int lastUserID = 0;
	string currentTradeItems = "";
	int respawnX = 0;
	int respawnY = 0;
	int skinColor = 0x8295C3FF; //normal SKin color like gt!
	PlayerInventory inventory;
	bool loadedInventory = false;
	int updateReq = 0;	
	long long int lastSB = 0;
	long long int lastPunchTime = 0;
	long long int lastHitTime = 0;
	long long int lastJoinReq = 0;
	bool hasJoinedFromSubServer = false;
	bool isBot = true;
	int pvpScore = 0;
	bool isQueuing = false;
	bool isWaitingForMatch = false;
	bool isInGame = false;
	bool queueEntered = false;
	uint32_t lavaHitAt = 0;
	uint32_t deadTime = 0;
	vector<WorldAdministration> worldBan;
};




struct PlayerMoving {
	int packetType;
	int netID;
	int secondnetID;
	float x;
	float y;
	int characterState;
	int plantingTree;
	float XSpeed;
	float YSpeed;
	int punchX;
	int punchY;
};

long long GetCurrentTimeInternal()
{
	using namespace std::chrono;
	return (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count();
}
long long GetCurrentTimeInternalSeconds()
{
	using namespace std::chrono;
	return (duration_cast<seconds>(system_clock::now().time_since_epoch())).count();
}



BYTE* packPlayerMoving(PlayerMoving* dataStruct)
{
	BYTE* data = new BYTE[64];
	for (int i = 0; i < 64; i++)
	{
		data[i] = 0;
	}
	memcpy(data, &dataStruct->packetType, 4);
	memcpy(data + 4, &dataStruct->netID, 4);	
	memcpy(data + 12, &dataStruct->characterState, 4);
	memcpy(data + 20, &dataStruct->plantingTree, 4);
	memcpy(data + 24, &dataStruct->x, 4);
	memcpy(data + 28, &dataStruct->y, 4);
	memcpy(data + 32, &dataStruct->XSpeed, 4);
	memcpy(data + 36, &dataStruct->YSpeed, 4);
	memcpy(data + 44, &dataStruct->punchX, 4);
	memcpy(data + 48, &dataStruct->punchY, 4);
	return data;
}

struct WorldItem {
	__int16 foreground = 0;
	__int16 background = 0;
	int breakLevel = 0;
	long long int breakTime = 0;
	bool activated = false;
	bool water = false;
	bool fire = false;
	bool glue = false;
	bool red = false;
	bool green = false;
	bool blue = false;
	// STUFF WEATHER VARS
	int gravity = 100;
	bool isInverted = false;
	bool isRotating = false;
	// STUFF WEATHER VARS (END)
	int clothHair;
	int clothHead;
	int clothMask;
	int clothHand;
	int clothNeck;
	int clothShirt;
	int clothPants;
	int clothFeet;
	int clothBack;
	int displayBlock = 0;
	string sign = "";

};

struct DroppedItem { // TODO
	int id;
	int uid;
	int count;
	float x;
	float y;
};

struct WorldInfo {
	int width = 100;
	int height = 60;
	string name = "TEST";
	string displayOwner = "";
	WorldItem* items;
	int itemcount = 0;
	string owner = "";
	int ownerId;
	int weather = 0;
	bool isNuked = false;
	bool isPublic = false;
	bool isCreated = false;
	int droppedCount = 0;
	vector<string> banned;
	vector<DroppedItem> droppedItems;		
	bool dropSized = false;
};



PlayerMoving* unpackPlayerMoving(BYTE* data)
{
	PlayerMoving* dataStruct = new PlayerMoving;		
	dataStruct->packetType = *(int*)(data);
	dataStruct->netID = *(int*)(data + 4);
	dataStruct->characterState = *(int*)(data + 12);
	dataStruct->plantingTree = *(int*)(data + 20);
	dataStruct->x = *(float*)(data + 24);
	dataStruct->y = *(float*)(data + 28);
	dataStruct->XSpeed = *(float*)(data + 32);
	dataStruct->YSpeed = *(float*)(data + 36);
	dataStruct->punchX = *(int*)(data + 44);
	dataStruct->punchY = *(int*)(data + 48);
	return dataStruct;
}

struct TileExtra {
	int packetType;
	int characterState;
	float objectSpeedX;
	int punchX;
	int punchY;
	int charStat;
	int blockid;
	int visual;
	int signs;
	int backgroundid;
	int displayblock;
	int time;
	int netID;
	int weatherspeed;
	int bpm;
	//int unused1;
	//int unused2;
	//int unused3;
	//int bpm;
};

void banLogin(ENetPeer* peer) {
	string text = "action|log\nmsg|`4Sorry, this account (`5" + ((PlayerInfo*)(peer->data))->rawName + "`4) has been suspended. `wNeed help? Contact the `!GTV3 Team`w.``";
	string text3 = "action|logon_fail\n";
	string dc = "https://discord.gg/6gmmK6z";
	string url = "action|set_url\nurl|" + dc + "\nlabel|Join GTV3 discord\n";


	BYTE* data = new BYTE[5 + text.length()];
	BYTE* data3 = new BYTE[5 + text3.length()];
	BYTE* dataurl = new BYTE[5 + url.length()];
	BYTE zero = 0;
	int type = 3;
	memcpy(data, &type, 4);
	memcpy(data + 4, text.c_str(), text.length());
	memcpy(data + 4 + text.length(), &zero, 1);

	memcpy(dataurl, &type, 4);
	memcpy(dataurl + 4, url.c_str(), url.length());
	memcpy(dataurl + 4 + url.length(), &zero, 1);

	memcpy(data3, &type, 4);
	memcpy(data3 + 4, text3.c_str(), text3.length());
	memcpy(data3 + 4 + text3.length(), &zero, 1);

	ENetPacket* p = enet_packet_create(data,
		5 + text.length(),
		ENET_PACKET_FLAG_RELIABLE);
	enet_peer_send(peer, 0, p);
	ENetPacket* p3 = enet_packet_create(dataurl,
		5 + url.length(),
		ENET_PACKET_FLAG_RELIABLE);
	enet_peer_send(peer, 0, p3);
	ENetPacket* p2 = enet_packet_create(data3,
		5 + text3.length(),
		ENET_PACKET_FLAG_RELIABLE);
	enet_peer_send(peer, 0, p2);

	delete data;
	delete dataurl;
	delete data3;
}

void sendWrench(ENetPeer* peer, string name, int gems, bool isWorldOwner, bool isAdmin, bool isHimSelf) {
	if (isAdmin) {
		if (isHimSelf == false) {
			GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\nadd_label_with_icon|big|`w" + name + "|left|18|\nadd_spacer|small|\nadd_label|small|`4Gems:`w " + to_string(gems) + "|left|4|\n\nadd_button|addfriendrnbutton|Add as friend|0|0|\nadd_button|pull|`5Pull|0|0|\nadd_button|kick|`4Kick|0|0|\nadd_button|wban|`4World Ban|0|0|\nadd_button|punishview|`!Punish/View|0|0|\nadd_spacer|small|\nadd_button||Continue playing|0|0|\nadd_quick_exit"));
			ENetPacket * packet = enet_packet_create(p.data,
				p.len,
				ENET_PACKET_FLAG_RELIABLE);
			enet_peer_send(peer, 0, packet);
			delete p.data;
			return;
		}
		else {
			GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\nadd_label_with_icon|big|`w" + name + "|left|18|\nadd_spacer|small|\nadd_label|small|`4Gems:`w " + to_string(gems) + "|left|4|\nadd_spacer|small|\nadd_button||Continue playing|0|0|\nadd_quick_exit"));
			ENetPacket * packet = enet_packet_create(p.data,
				p.len,
				ENET_PACKET_FLAG_RELIABLE);
			enet_peer_send(peer, 0, packet);
			delete p.data;
			return;
		}
	}
	else if (isWorldOwner) {
		if (isHimSelf == false) {
			GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\nadd_label_with_icon|big|`w" + name + "|left|18|\nadd_spacer|small|\nadd_label|small|`4Gems:`w " + to_string(gems) + "|left|4|\n\nadd_button|addfriendrnbutton|Add as friend|0|0|\nadd_button|pull|`5Pull|0|0|\nadd_button|kick|`4Kick|0|0|\nadd_button|wban|`4World Ban|0|0|\nadd_spacer|small|\nadd_button||Continue playing|0|0|\nadd_quick_exit"));
			ENetPacket * packet = enet_packet_create(p.data,
				p.len,
				ENET_PACKET_FLAG_RELIABLE);
			enet_peer_send(peer, 0, packet);
			delete p.data;
			return;
		}
		else {
			GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\nadd_label_with_icon|big|`w" + name + "|left|18|\nadd_spacer|small|\nadd_label|small|`4Gems:`w " + to_string(gems) + "|left|4|\nadd_spacer|small|\nadd_button||Continue playing|0|0|\nadd_quick_exit"));
			ENetPacket * packet = enet_packet_create(p.data,
				p.len,
				ENET_PACKET_FLAG_RELIABLE);
			enet_peer_send(peer, 0, packet);
			delete p.data;
			return;
		}
	}
	else {
		if (isHimSelf == false) {
			GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\nadd_label_with_icon|big|`w" + name + "|left|18|\nadd_spacer|small|\nadd_label|small|`4Gems:`w " + to_string(gems) + "|left|4|\n\nadd_button|addfriendrnbutton|Add as friend|0|0|\nadd_spacer|small|\nadd_button||Continue playing|0|0|\nadd_quick_exit"));
			ENetPacket * packet = enet_packet_create(p.data,
				p.len,
				ENET_PACKET_FLAG_RELIABLE);
			enet_peer_send(peer, 0, packet);
			delete p.data;
			return;
		}
		else {
			GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\nadd_label_with_icon|big|`w" + name + "|left|18|\nadd_spacer|small|\nadd_label|small|`4Gems:`w " + to_string(gems) + "|left|4|\nadd_spacer|small|\nadd_button||Continue playing|0|0|\nadd_quick_exit"));
			ENetPacket * packet = enet_packet_create(p.data,
				p.len,
				ENET_PACKET_FLAG_RELIABLE);
			enet_peer_send(peer, 0, packet);
			delete p.data;
			return;
		}
	}
}

void sendPunishDialog(ENetPeer* peer, bool evade, bool isAdmin, string name, string ip, string rid, string sid, string mac) {
	if (isAdmin) {
		GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`wEditing Player: ``" + name + "|left|658|\nadd_label|small|`wProper IP / Identification: (?)" + "|left|4|\n\nadd_spacer|small|\nadd_label|small|`wMAC: ?|left|4|\nadd_label|small|`wRID: ?|left|4|\nadd_label|small|`wSID: ?|left|4|\n\nadd_spacer|small|\nadd_quick_exit|\nadd_button|chc0|Close|noflags|0|0|\nnend_dialog|gazette||OK|"));
		ENetPacket * packet = enet_packet_create(p.data,
			p.len,
			ENET_PACKET_FLAG_RELIABLE);
		enet_peer_send(peer, 0, packet);

		//enet_host_flush(server);
		delete p.data;
	}
	else if (evade) {
		GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`wEditing Player: ``" + name + "|left|658|\nadd_label|small|`wProper IP / Identification: (" + ip + ")|left|4|\n\nadd_spacer|small|\nadd_label|small|`wMAC: " + mac + "|left|4|\nadd_label|small|`wRID: " + rid + "|left|4|\nadd_label|small|`wSID: " + sid + "|left|4|\nadd_smalltext|`w-> Evade detected!|left|4|\n\nadd_spacer|small|\nadd_label_with_icon_button||`1Freeze!||274|freeze|\nadd_label_with_icon_button||`w<-- `oTape for nasty words.||408|tape|\n\nadd_spacer|small|\nadd_label_with_icon_button||`w<-- `o2 week DGH||276|ban7|\nadd_label_with_icon_button||`w<-- `o4 week DGH||276|name|\nadd_label_with_icon_button||`w<-- `o8 week DGH||276|name|\nadd_label_with_icon_button||`w<-- `oPerma ban DGH||276|suspend|\nadd_label_with_icon_button||`w<-- `oPerma ban for hacking||276|suspendip|\nadd_spacer|small|\nadd_label_with_icon_button||`w<-- `oBoot! (Disconnect player)||1908|disconnect|\nadd_spacer|small|\nadd_quick_exit|\nadd_button|chc0|Close|noflags|0|0|\nnend_dialog|gazette||OK|"));
		ENetPacket * packet = enet_packet_create(p.data,
			p.len,
			ENET_PACKET_FLAG_RELIABLE);
		enet_peer_send(peer, 0, packet);

		//enet_host_flush(server);
		delete p.data;
	}
	else {
		GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`wEditing Player: ``" + name + "|left|658|\nadd_label|small|`wProper IP / Identification: (" + ip + ")|left|4|\n\nadd_spacer|small|\nadd_label|small|`wMAC: " + mac + "|left|4|\nadd_label|small|`wRID: " + rid + "|left|4|\nadd_label|small|`wSID: " + sid + "|left|4|\n\nadd_spacer|small|\nadd_label_with_icon_button||`1Freeze!||274|freeze|\nadd_label_with_icon_button||`w<-- `oTape for nasty words.||408|tape|\n\nadd_spacer|small|\nadd_label_with_icon_button||`w<-- `o2 week DGH||276|ban7|\nadd_label_with_icon_button||`w<-- `o4 week DGH||276|name|\nadd_label_with_icon_button||`w<-- `o8 week DGH||276|name|\nadd_label_with_icon_button||`w<-- `oPerma ban DGH||276|suspend|\nadd_label_with_icon_button||`w<-- `oPerma ban for hacking||276|suspendip|\nadd_spacer|small|\nadd_label_with_icon_button||`w<-- `oBoot! (Disconnect player)||1908|disconnect|\nadd_spacer|small|\nadd_quick_exit|\nadd_button|chc0|Close|noflags|0|0|\nnend_dialog|gazette||OK|"));
		ENetPacket * packet = enet_packet_create(p.data,
			p.len,
			ENET_PACKET_FLAG_RELIABLE);
		enet_peer_send(peer, 0, packet);
		delete p.data;
	}
}

string OutputBanTime(int n)
{
	string x;
	int day = n / (24 * 3600);
	if (day != 0) x.append(to_string(day) + " Days ");
	n = n % (24 * 3600);
	int hour = n / 3600;
	if (hour != 0) x.append(to_string(hour) + " Hours ");
	n %= 3600;
	int minutes = n / 60;
	if (minutes != 0) x.append(to_string(minutes) + " Minutes ");
	n %= 60;
	int seconds = n;
	if (seconds!= 0) x.append(to_string(seconds) + " Seconds");
	return x;
}




int calcBanDuration(long long banDuration) {
	int duration = 0;
	duration = banDuration - GetCurrentTimeInternalSeconds();
	return duration;
}

void banLoginDevice(ENetPeer* peer, long long banDurationDefault, string sid, string mac) {

	int bantimeleft = calcBanDuration(banDurationDefault);
	if (bantimeleft < 1) {
				
		return;
	}
	string text = "action|log\nmsg|`4Sorry, this device or location is still banned for `w" + OutputBanTime(calcBanDuration(banDurationDefault)) + ". Need help? Contact the `!GTV3 Team`w.``";
	string text3 = "action|logon_fail\n";
	string dc = "https://discord.gg/6gmmK6z";
	string url = "action|set_url\nurl|" + dc + "\nlabel|Join GTV3 discord\n";


	BYTE* data = new BYTE[5 + text.length()];
	BYTE* data3 = new BYTE[5 + text3.length()];
	BYTE* dataurl = new BYTE[5 + url.length()];
	BYTE zero = 0;
	int type = 3;
	memcpy(data, &type, 4);
	memcpy(data + 4, text.c_str(), text.length());
	memcpy(data + 4 + text.length(), &zero, 1);

	memcpy(dataurl, &type, 4);
	memcpy(dataurl + 4, url.c_str(), url.length());
	memcpy(dataurl + 4 + url.length(), &zero, 1);

	memcpy(data3, &type, 4);
	memcpy(data3 + 4, text3.c_str(), text3.length());
	memcpy(data3 + 4 + text3.length(), &zero, 1);

	ENetPacket* p = enet_packet_create(data,
		5 + text.length(),
		ENET_PACKET_FLAG_RELIABLE);
	enet_peer_send(peer, 0, p);
	ENetPacket* p3 = enet_packet_create(dataurl,
		5 + url.length(),
		ENET_PACKET_FLAG_RELIABLE);
	enet_peer_send(peer, 0, p3);
	ENetPacket* p2 = enet_packet_create(data3,
		5 + text3.length(),
		ENET_PACKET_FLAG_RELIABLE);
	enet_peer_send(peer, 0, p2);
	enet_peer_disconnect_later(peer, 0);
	delete data;
	delete dataurl;
	delete data3;
}

void checkBan(ENetPeer* peer) {
	string rid = ((PlayerInfo*)(peer->data))->rid;
	string sid = ((PlayerInfo*)(peer->data))->sid;
	string gid = ((PlayerInfo*)(peer->data))->gid;
	string vid = ((PlayerInfo*)(peer->data))->vid;
	string aid = ((PlayerInfo*)(peer->data))->aid;
	string mac = ((PlayerInfo*)(peer->data))->mac;
	string ip = to_string(peer->address.host);
	Remove(mac, ":");
	bool exist = experimental::filesystem::exists("bans/rid/" + rid + ".txt") ||
		experimental::filesystem::exists("bans/sid/" + sid + ".txt") ||
		experimental::filesystem::exists("bans/gid/" + gid + ".txt") ||
		experimental::filesystem::exists("bans/vid/" + vid + ".txt") ||
		experimental::filesystem::exists("bans/aid/" + aid + ".txt") ||
		experimental::filesystem::exists("bans/mac/" + mac + ".txt") ||
		experimental::filesystem::exists("bans/ip/" + ip + ".txt");	
	if (exist) {
		string content = "0";
		if (experimental::filesystem::exists("bans/ip/" + ip + ".txt")) {
			std::ifstream ifs("bans/ip/" + ip + ".txt");
			std::string contentf((std::istreambuf_iterator<char>(ifs)),
				(std::istreambuf_iterator<char>()));
			content = contentf;
		}
		else if (experimental::filesystem::exists("bans/sid/" + sid + ".txt")) {
			std::ifstream ifs("bans/sid/" + sid + ".txt");
			std::string contentf((std::istreambuf_iterator<char>(ifs)),
				(std::istreambuf_iterator<char>()));
			content = contentf;
		}		
		else if (experimental::filesystem::exists("bans/sid/" + sid + ".txt")) {
			std::ifstream ifs("bans/mac/" + mac + ".txt");
			std::string contentf((std::istreambuf_iterator<char>(ifs)),
				(std::istreambuf_iterator<char>()));
			content = contentf;
		}
		if (content != "0") {
			long long banDuration = atoi(content.c_str());
			banLoginDevice(peer, banDuration, sid, mac);
		}
	}
}

bool isValidID(const string s) {
	return s.find_first_not_of("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz") == string::npos;
}

void autoBan(ENetPeer* peer, bool isInvalid, long long timeInH) {
	ofstream x;
	ofstream e;
	ofstream b;
	if (isInvalid) {
		x.open("bans/ip/" + to_string(peer->address.host) + ".txt");
		x << to_string(GetCurrentTimeInternalSeconds() + (timeInH * 3600));
		x.close();
		enet_peer_disconnect_later(peer, 0);
	}
	else {
		string mac = ((PlayerInfo*)(peer->data))->mac;
		Remove(mac, ":");
		x.open("bans/ip/" + to_string(peer->address.host) + ".txt");
		x << to_string(GetCurrentTimeInternalSeconds() + (timeInH * 3600));
		x.close();
		if (isValidID(((PlayerInfo*)(peer->data))->sid)) {
			e.open("bans/sid/" + ((PlayerInfo*)(peer->data))->sid + ".txt");
			e << to_string(GetCurrentTimeInternalSeconds() + (timeInH * 3600));
			e.close();
		}
		if (isValidID(mac)) {
			b.open("bans/mac/" + mac + ".txt");
			b << to_string(GetCurrentTimeInternalSeconds() + (timeInH * 3600));
			b.close();
		}
		
		enet_peer_disconnect_later(peer, 0);
	}
}

void savePlayer(ENetPeer* peer) {
	if (((PlayerInfo*)(peer->data))->gems > -1) {
		
		int qstate = 0;
		conn = mysql_init(0);
		conn = mysql_real_connect(conn, ip, user, pass, database, 0, NULL, 0);
		if (conn == NULL) {			
			return;
		}
		if (conn != NULL) {
			stringstream ss;

			ss << "UPDATE players SET gems = '" + to_string(((PlayerInfo*)(peer->data))->gems) + "', skincolor = '" + to_string(((PlayerInfo*)(peer->data))->skinColor) + "', hair = '" + to_string(((PlayerInfo*)(peer->data))->cloth_hair) + "', shirt = '" + to_string(((PlayerInfo*)(peer->data))->cloth_shirt) + "', pants = '" + to_string(((PlayerInfo*)(peer->data))->cloth_pants) + "', feet = '" + to_string(((PlayerInfo*)(peer->data))->cloth_feet) + "', face = '" + to_string(((PlayerInfo*)(peer->data))->cloth_face) + "', hand = '" + to_string(((PlayerInfo*)(peer->data))->cloth_hand) + "', back = '" + to_string(((PlayerInfo*)(peer->data))->cloth_back) + "', mask = '" + to_string(((PlayerInfo*)(peer->data))->cloth_mask) + "', neck = '" + to_string(((PlayerInfo*)(peer->data))->cloth_necklace) + "', ances = '" + to_string(((PlayerInfo*)(peer->data))->cloth_ances) + "', Ghost = '" + to_string(((PlayerInfo*)(peer->data))->canWalkInBlocks) + "', invis = '" + to_string(((PlayerInfo*)(peer->data))->isinv) + "' WHERE username = '" << ((PlayerInfo*)(peer->data))->rawName << "'";
			string query = ss.str(); // loading query into string
			const char* q = query.c_str(); // converting string to const char
			qstate = mysql_query(conn, q);
			if (qstate == 0) { // if qstate == 0 (EVERYTHING IS OK!) then pop out a 1, 1 will lead to the dialog that will say ("GrowID Created")		
				//TODO			
			}
			else {

			}
		}
		mysql_close(conn);
	
	}
}

void sendGazette(ENetPeer* peer) {
	GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"),
		"set_default_color|`o\n\nadd_label_with_icon|big|`wThe GTV3 Gazette``|left|5016|\n\nadd_spacer|small|\nadd_label_with_icon|small|`pWelcome to `4GTV3 `w[Version 0.15]``|left|9140|\nadd_label|big|`rThe Team:``|left|4|\nadd_spacer|small|\nadd_label|small|`o-`6@Esto (mar4ello6)``|left|4|\nadd_label|small|`o-`6@iProgramInCpp``|left|4|\nadd_label|small|`o-`6@ness``|left|4|\nadd_label|small|`o-`6@playingo``|left|4|\nadd_label|small|`o-`6@Nabsi `w(Organization)``|left|4|\nadd_label|small|`o-`6@Finland `w(Drawing & Arts & Hosting)``|left|4|\nadd_spacer|big|\nadd_label|small|`p[0.15] World/Mod Management & Improvements added.``|left|4|\nadd_smalltext|`#iOS users will not have custom items as it is not supported for them yet.|\nadd_label|small|`wWhat's new: BPM Changer / New World Lock Settings, saving data `wand bug fixes!|left|4|\nadd_label|big|`wEnjoy playing on our server!|left|4|\nadd_button|isbot|`bContinue `o(`2click here`o)``|noflags|0|0|\nnend_dialog|gazette||OK|"));
	ENetPacket * packet = enet_packet_create(p.data,
		p.len,
		ENET_PACKET_FLAG_RELIABLE);
	enet_peer_send(peer, 0, packet);
	delete p.data;
}

void sendHelp(ENetPeer* peer, int adminLevel) {
	if (adminLevel == 0) {
		Player::OnConsoleMessage(peer, "Help >> /mods /help /mod /inventory /give (id, amount) /color (id) /who /count /sb /alt /radio /jsb /find <item name> /unequip /weather (id) /flag (id) /kickall /pull");		
	}
	else if (adminLevel == 1) {
		Player::OnConsoleMessage(peer, "Help >> /mods /help /mod /inventory /give (id, amount) /color (id) /who /count /sb /alt /radio /jsb /find <item name> /unequip /weather (id) /flag (id) /kickall /pull /tape /warp /pullall /nick");
	}
	else if (adminLevel == 2) {
		Player::OnConsoleMessage(peer, "Help >> /mods /help /mod /inventory /give (id, amount) /color (id) /who /count /sb /alt /radio /jsb /find <item name> /unequip /weather (id) /flag (id) /kickall /pull /tape /warp /warpto /pullall /nick /banworld /curse /ghost /invis /boot");
	}
	else if (adminLevel == 3) {
		Player::OnConsoleMessage(peer, "Help >> /mods /help /mod /inventory /give (id, amount) /color (id) /who /count /sb /alt /radio /jsb /find <item name> /unequip /weather (id) /flag (id) /kickall /pull /tape /warp /warpto /pullall /nick /banworld /curse /ghost /invis /nuke /ban /info /infoex /findex /massban /masscurse /masstape /massfreeze /remove /renameworld /boot");
	}
	else if (adminLevel == 4) {
		Player::OnConsoleMessage(peer, "Help >> /mods /help /mod /inventory /give (id, amount) /color (id) /who /count /sb /alt /radio /jsb /find <item name> /unequip /weather (id) /flag (id) /kickall /pull /tape /warp /warpto /pullall /nick /banworld /curse /ghost /invis /nuke /ban /info /infoex /findex /massban /masscurse /masstape /massfreeze /remove /renameworld /debug /clearworld /edit /increase /boot");
	}
}

void sendInventory(ENetPeer* peer, PlayerInventory inventory)
{
	string asdf2 = "0400000009A7379237BB2509E8E0EC04F8720B050000000000000000FBBB0000010000007D920100FDFDFDFD04000000040000000000000000000000000000000000";
	int inventoryLen = inventory.items.size();
	int packetLen = (asdf2.length() / 2) + (inventoryLen * 4) + 4;
	BYTE* data2 = new BYTE[packetLen];
	for (int i = 0; i < asdf2.length(); i += 2)
	{
		char x = ch2n(asdf2[i]);
		x = x << 4;
		x += ch2n(asdf2[i + 1]);
		memcpy(data2 + (i / 2), &x, 1);
	}
	int endianInvVal = _byteswap_ulong(inventoryLen);
	memcpy(data2 + (asdf2.length() / 2) - 4, &endianInvVal, 4);
	endianInvVal = _byteswap_ulong(inventory.inventorySize);
	memcpy(data2 + (asdf2.length() / 2) - 8, &endianInvVal, 4);
	int val = 0;
	for (int i = 0; i < inventoryLen; i++)
	{
		val = 0;
		val |= inventory.items.at(i).itemID;
		val |= inventory.items.at(i).itemCount << 16;
		val &= 0x00FFFFFF;
		val |= 0x00 << 24;
		memcpy(data2 + (i * 4) + (asdf2.length() / 2), &val, 4);
	}
	ENetPacket * packet3 = enet_packet_create(data2,
		packetLen,
		ENET_PACKET_FLAG_RELIABLE);
	enet_peer_send(peer, 0, packet3);
	delete data2;
	//enet_host_flush(server);
}

void SendPacketRaw(int a1, void *packetData, size_t packetDataSize, void *a4, ENetPeer* peer, int packetFlag)
{
	ENetPacket *p;

	if (peer) // check if we have it setup
	{
		if (a1 == 4 && *((BYTE *)packetData + 12) & 8)
		{
			p = enet_packet_create(0, packetDataSize + *((DWORD *)packetData + 13) + 5, packetFlag);
			int four = 4;
			memcpy(p->data, &four, 4);
			memcpy((char *)p->data + 4, packetData, packetDataSize);
			memcpy((char *)p->data + packetDataSize + 4, a4, *((DWORD *)packetData + 13));
			enet_peer_send(peer, 0, p);
		}
		else
		{
			p = enet_packet_create(0, packetDataSize + 5, packetFlag);
			memcpy(p->data, &a1, 4);
			memcpy((char *)p->data + 4, packetData, packetDataSize);
			enet_peer_send(peer, 0, p);
		}
	}
	delete (char*)packetData;
}




BYTE* packBlockVisual(TileExtra* dataStruct)
{
	
	BYTE* data = new BYTE[104]; // 96
	for (int i = 0; i < 100; i++)
	{
		data[i] = 0;
	}
	memcpy(data, &dataStruct->packetType, 4);
	memcpy(data + 8, &dataStruct->netID, 4);
	memcpy(data + 12, &dataStruct->characterState, 4);
	memcpy(data + 16, &dataStruct->objectSpeedX, 4);
	//memcpy(data + 40, &dataStruct->bpm, 4);
	memcpy(data + 44, &dataStruct->punchX, 4);
	memcpy(data + 48, &dataStruct->punchY, 4);
	memcpy(data + 52, &dataStruct->charStat, 4);
	memcpy(data + 56, &dataStruct->blockid, 2);
	memcpy(data + 58, &dataStruct->backgroundid, 2);
	memcpy(data + 60, &dataStruct->visual, 4);
	memcpy(data + 64, &dataStruct->displayblock, 4);
	

	return data;
}


bool isHere(ENetPeer* peer, ENetPeer* peer2)
{
	return ((PlayerInfo*)(peer->data))->currentWorld == ((PlayerInfo*)(peer2->data))->currentWorld;
}

void Player::OnInvis(ENetPeer* peer, int state, int netID) {
	GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnInvis"), state));
	memcpy(p.data + 8, &netID, 4);
	ENetPacket * packet = enet_packet_create(p.data,
		p.len,
		ENET_PACKET_FLAG_RELIABLE);
	enet_peer_send(peer, 0, packet);
	delete p.data;
}

void Player::OnFailedToEnterWorld(ENetPeer* peer) {
	GamePacket p = packetEnd(appendIntx(appendString(createPacket(), "OnFailedToEnterWorld"), 1));
	ENetPacket* packet = enet_packet_create(p.data,
		p.len,
		ENET_PACKET_FLAG_RELIABLE);
	enet_peer_send(peer, 0, packet);
	delete p.data;
}

void Player::OnTextOverlay(ENetPeer* peer, string text) {
	GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnTextOverlay"), text));	
	ENetPacket * packet = enet_packet_create(p.data,
		p.len,
		ENET_PACKET_FLAG_RELIABLE);
	enet_peer_send(peer, 0, packet);
	delete p.data;
}

void Player::OnKilled(ENetPeer* peer, int netID) {
	GamePacket p = packetEnd(appendString(createPacket(), "OnKilled"));
	memcpy(p.data + 8, &netID, 4);
	ENetPacket * packet = enet_packet_create(p.data,
		p.len,
		ENET_PACKET_FLAG_RELIABLE);
	enet_peer_send(peer, 0, packet);
	delete p.data;
}

void Player::SetRespawnPos(ENetPeer* peer, int posX, int posY, int netID) {
	GamePacket p22 = packetEnd(appendInt(appendString(createPacket(), "SetRespawnPos"), posX + posY)); // (world->width * posY)
	memcpy(p22.data + 8, &netID, 4);
	ENetPacket* packet22 = enet_packet_create(p22.data,
		p22.len,
		ENET_PACKET_FLAG_RELIABLE);
	enet_peer_send(peer, 0, packet22);
	delete p22.data;
}







void addWorldBan(ENetPeer* peer, int userID) {

}

void InitializePacketWithDisplayBlock(BYTE* raw)
{
	int i = 0;
	raw[i] = 0x05; i++; // 0
	raw[i] = 0x00; i++; 
	raw[i] = 0x00; i++; 
	raw[i] = 0x00; i++;
	raw[i] = 0x00; i++; // 4
	raw[i] = 0x00; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x00; i++; // 8
	raw[i] = 0x00; i++; 
	raw[i] = 0x00; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x08; i++; // 12
	raw[i] = 0x00; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x00; i++; // 16
	raw[i] = 0x00; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x00; i++; // 20
	raw[i] = 0x00; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x00; i++; // 24
	raw[i] = 0x00; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x00; i++; // 28
	raw[i] = 0x00; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x00; i++; // 32
	raw[i] = 0x00; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x00; i++; // 36
	raw[i] = 0x00; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x00; i++; // 40
	raw[i] = 0x00; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0xff; i++; // 44
	raw[i] = 0x00; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0xff; i++; // 48
	raw[i] = 0x00; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x00; i++; // 52
	raw[i] = 0x00; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x82; i++;
	raw[i] = 0x0b; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x01; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x17; i++;
	raw[i] = 0x82; i++;
	raw[i] = 0x04; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x6c; i++;
	raw[i] = 0xfd; i++;
	raw[i] = 0xfd; i++;
	raw[i] = 0xfd; i++;
}

void updateDisplayVisuals(ENetPeer* peer, int foreground, int x, int y, int background, int itemid, bool sendPacketToEveryone = true)
{
	
	int plength = 74;
	BYTE* raw = new BYTE[plength];
	memset(raw, 0, plength);
	InitializePacketWithDisplayBlock(raw);

	memcpy(raw + 44, &x, sizeof(int));
	memcpy(raw + 48, &y, sizeof(int));
	memcpy(raw + 56, &foreground, sizeof(short));
	memcpy(raw + 58, &background, sizeof(short));
	memcpy(raw + 65, &itemid, sizeof(int));

	ENetPacket* p = enet_packet_create(0, plength + 4, ENET_PACKET_FLAG_RELIABLE);
	int four = 4;
	memcpy(p->data, &four, sizeof(int));
	memcpy((char*)p->data + 4, raw, plength);

	if (sendPacketToEveryone)
	{
		ENetPeer* currentPeer;
		for (currentPeer = server->peers;
			currentPeer < &server->peers[server->peerCount];
			++currentPeer)
		{
			if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
				continue;
			if (isHere(peer, currentPeer)) {
				enet_peer_send(currentPeer, 0, p);
			}
		}
		delete raw;
	}
	else
	{
		enet_peer_send(peer, 0, p);
		delete raw;
	}
}

void Player::OnZoomCamera(ENetPeer * peer, float value1, int value2) {
	GamePacket p = packetEnd(appendIntx(appendFloat(appendString(createPacket(), "OnZoomCamera"), value1), value2));
	ENetPacket* packet = enet_packet_create(p.data,
		p.len,
		ENET_PACKET_FLAG_RELIABLE);
	enet_peer_send(peer, 0, packet);
	delete p.data;
}



void Player::SmoothZoom(ENetPeer* peer) {
	GamePacket p = packetEnd(appendIntx(appendFloat(appendString(createPacket(), "OnZoomCamera"), 10000.0f), 1000));
	ENetPacket* packet = enet_packet_create(p.data,
		p.len,
		ENET_PACKET_FLAG_RELIABLE);
	enet_peer_send(peer, 0, packet);
	delete p.data;
}

void Player::OnRaceStart(ENetPeer * peer, int netID)
{
	GamePacket p = packetEnd(appendString(createPacket(), "OnRaceStart"));
	memcpy(p.data + 8, &netID, 4);
	ENetPacket* packet = enet_packet_create(p.data,
		p.len,
		ENET_PACKET_FLAG_RELIABLE);
	enet_peer_send(peer, 0, packet);
	delete p.data;
}

void Player::OnRaceEnd(ENetPeer * peer, int netID)
{
	GamePacket p = packetEnd(appendString(createPacket(), "OnRaceStart"));
	memcpy(p.data + 8, &netID, 4);
	ENetPacket* packet = enet_packet_create(p.data,
		p.len,
		ENET_PACKET_FLAG_RELIABLE);
	enet_peer_send(peer, 0, packet);
	delete p.data;
}

void Player::Ping(ENetPeer * peer)
{
	GamePacket p = packetEnd(appendString(createPacket(), "Ping"));	
	ENetPacket* packet = enet_packet_create(p.data,
		p.len,
		ENET_PACKET_FLAG_RELIABLE);
	enet_peer_send(peer, 0, packet);
	delete p.data;
}

void Player::OnDialogRequest(ENetPeer * peer, string args)
{
	GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), args));
	ENetPacket* packet = enet_packet_create(p.data,
		p.len,
		ENET_PACKET_FLAG_RELIABLE);
	enet_peer_send(peer, 0, packet);	
	delete p.data;
}

void Player::OnSetPos(ENetPeer* peer, int netID, int x, int y) {
	GamePacket p = packetEnd(appendFloat(appendString(createPacket(), "OnSetPos"), x, y));
	memcpy(p.data + 8, &netID, 4);
	ENetPacket * packet = enet_packet_create(p.data,
		p.len,
		ENET_PACKET_FLAG_RELIABLE);
	enet_peer_send(peer, 0, packet);
	delete p.data;
}

void Player::OnSetFreezeState(ENetPeer* peer, int state, int netID) {
	GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnSetFreezeState"), state));
	memcpy(p.data + 8, &netID, 4);
	ENetPacket* packet = enet_packet_create(p.data,
		p.len,
		ENET_PACKET_FLAG_RELIABLE);
	enet_peer_send(peer, 0, packet);
	delete p.data;
}

void Player::OnSetCurrentWeather(ENetPeer* peer, int weather) {
	GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnSetCurrentWeather"), weather));
	ENetPacket* packet = enet_packet_create(p.data,
		p.len,
		ENET_PACKET_FLAG_RELIABLE);
	enet_peer_send(peer, 0, packet);
	delete p.data;
}

void Player::OnTradeStatus(ENetPeer * peer, int netIDOther, string offerstatus, string offer)
{
	//"add_slot|20|3locked|0reset_locks|1accepted|1"
	GamePacket p = packetEnd(appendString(appendString(appendString(appendInt(appendString(createPacket(), "OnTradeStatus"), netIDOther), ""), offerstatus + "'s offer"), offer));
	ENetPacket * packet = enet_packet_create(p.data,
		p.len,
		ENET_PACKET_FLAG_RELIABLE);
	enet_peer_send(peer, 0, packet);
	delete p.data;
}

void Player::OnSetBux(ENetPeer * peer, int gems, int accountstate)
{
	GamePacket p = packetEnd(appendInt(appendInt(appendString(createPacket(), "OnSetBux"), gems), accountstate));
	ENetPacket * packet = enet_packet_create(p.data,
		p.len,
		ENET_PACKET_FLAG_RELIABLE);

	enet_peer_send(peer, 0, packet);
	delete p.data;
}

void Player::OnParticleEffect(ENetPeer* peer, int effect, float x, float y, int delay) {
	GamePacket p = packetEnd(appendFloat(appendIntx(appendString(createPacket(), "OnParticleEffect"), effect), x, y));
	int deathFlag = 0x19;
	memcpy(p.data + 24, &delay, 4);
	memcpy(p.data + 56, &deathFlag, 4);
	ENetPacket* packet = enet_packet_create(p.data,
		p.len,
		ENET_PACKET_FLAG_RELIABLE);
	enet_peer_send(peer, 0, packet);
	delete p.data;
}

void Player::SetHasGrowID(ENetPeer * peer, int status, string username, string password)
{
	GamePacket p2 = packetEnd(appendString(appendString(appendInt(appendString(createPacket(), "SetHasGrowID"), status), username), password));
	ENetPacket * packet2 = enet_packet_create(p2.data,
		p2.len,
		ENET_PACKET_FLAG_RELIABLE);
	enet_peer_send(peer, 0, packet2);
	delete p2.data;
}

void Player::OnNameChanged(ENetPeer * peer, int netID, string name)
{
	GamePacket p3 = packetEnd(appendString(appendString(createPacket(), "OnNameChanged"), "`0`0" + name));
	memcpy(p3.data + 8, &netID, 4);
	ENetPacket * packet3 = enet_packet_create(p3.data,
		p3.len,
		ENET_PACKET_FLAG_RELIABLE);
	ENetPeer * currentPeer;
	for (currentPeer = server->peers;
		currentPeer < &server->peers[server->peerCount];
		++currentPeer)
	{
		if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
			continue;
		if (isHere(peer, currentPeer))
		{
			enet_peer_send(currentPeer, 0, packet3);
		}
	}
	delete p3.data;
}

void Player::OnSendToServer(ENetPeer * peer, int userID, int token, string ip, int port, string doorId, int lmode)
{
	auto p = packetEnd(appendInt(appendString(appendInt(appendInt(appendInt(appendString(createPacket(), "OnSendToServer"), port), token), userID), ip + "|" + doorId), lmode));
	ENetPacket* packet = enet_packet_create(p.data,
		p.len,
		ENET_PACKET_FLAG_RELIABLE);
	enet_peer_send(peer, 0, packet);
	delete p.data;
}

void Player::OnChangeSkin(ENetPeer* peer, int skinColor, int netID) {
	auto p = packetEnd(appendInt(appendString(createPacket(), "OnChangeSkin"), skinColor));
	memcpy(p.data + 8, &netID, 4);
	ENetPacket* packet = enet_packet_create(p.data,
		p.len,
		ENET_PACKET_FLAG_RELIABLE);
	enet_peer_send(peer, 0, packet);
	delete p.data;	
}

void Player::OnCountdownStart(ENetPeer* peer, int netID, int time, int score) {	
	if (score == -1) {
		auto p = packetEnd(appendInt(appendString(createPacket(), "OnCountdownStart"), time));
		memcpy(p.data + 8, &netID, 4);
		ENetPacket* packet = enet_packet_create(p.data,
			p.len,
			ENET_PACKET_FLAG_RELIABLE);
		enet_peer_send(peer, 0, packet);
		delete p.data;
	}
	else
	{
		auto p = packetEnd(appendInt(appendInt(appendString(createPacket(), "OnCountdownStart"), time), score));
		memcpy(p.data + 8, &netID, 4);
		ENetPacket* packet = enet_packet_create(p.data,
			p.len,
			ENET_PACKET_FLAG_RELIABLE);
		enet_peer_send(peer, 0, packet);
		delete p.data;
	}
}

void playerRespawn(ENetPeer* peer, bool isDeadByTile) {
	int netID = ((PlayerInfo*)(peer->data))->netID;
	if (isDeadByTile == false) {
		Player::OnKilled(peer, ((PlayerInfo*)(peer->data))->netID);
	}
	GamePacket p2x = packetEnd(appendInt(appendString(createPacket(), "OnSetFreezeState"), 0));
	memcpy(p2x.data + 8, &netID, 4);
	int respawnTimeout = 2000;
	int deathFlag = 0x19;
	memcpy(p2x.data + 24, &respawnTimeout, 4);
	memcpy(p2x.data + 56, &deathFlag, 4);
	ENetPacket* packet2x = enet_packet_create(p2x.data,
		p2x.len,
		ENET_PACKET_FLAG_RELIABLE);
	enet_peer_send(peer, 0, packet2x);
	delete p2x.data;
	Player::OnSetFreezeState(peer, 2, netID);
	GamePacket p2 = packetEnd(appendFloat(appendString(createPacket(), "OnSetPos"), ((PlayerInfo*)(peer->data))->respawnX, ((PlayerInfo*)(peer->data))->respawnY));
	memcpy(p2.data + 8, &(((PlayerInfo*)(peer->data))->netID), 4);
	respawnTimeout = 2000;	
	memcpy(p2.data + 24, &respawnTimeout, 4);
	memcpy(p2.data + 56, &deathFlag, 4);
	ENetPacket* packet2 = enet_packet_create(p2.data,
		p2.len,
		ENET_PACKET_FLAG_RELIABLE);
	enet_peer_send(peer, 0, packet2);
	delete p2.data;
	GamePacket p2a = packetEnd(appendString(appendString(createPacket(), "OnPlayPositioned"), "audio/teleport.wav"));
	memcpy(p2a.data + 8, &netID, 4);
	respawnTimeout = 2000;
	memcpy(p2a.data + 24, &respawnTimeout, 4);
	memcpy(p2a.data + 56, &deathFlag, 4);
	ENetPacket* packet2a = enet_packet_create(p2a.data,
		p2a.len,
		ENET_PACKET_FLAG_RELIABLE);
	enet_peer_send(peer, 0, packet2a);
	delete p2a.data;
}

string lockTileDatas(int visual, uint32_t owner, uint32_t adminLength, uint32_t* admins, bool isPublic = false, uint8_t bpm = 0) {
	string data;
	data.resize(4 + 2 + 4 + 4 + adminLength * 4 + 8);
	if (bpm) data.resize(data.length() + 4);
	data[2] = 0x01;
	if (isPublic) data[2] |= 0x80;
	data[4] = 3;
	data[5] = visual; // or 0x02
	STRINT(data, 6) = owner;
	//data[14] = 1;
	STRINT(data, 10) = adminLength;
	for (uint32_t i = 0; i < adminLength; i++) {
		STRINT(data, 14 + i * 4) = admins[i];
	}

	if (bpm) {
		STRINT(data, 10)++;
		STRINT(data, 14 + adminLength * 4) = -bpm;
	}
	return data;
}

string packPlayerMoving2(PlayerMoving* dataStruct)
{
	string data;
	data.resize(56);
	STRINT(data, 0) = dataStruct->packetType;
	STRINT(data, 4) = dataStruct->netID;
	STRINT(data, 12) = dataStruct->characterState;
	STRINT(data, 20) = dataStruct->plantingTree;
	STRINT(data, 24) = *(int*)&dataStruct->x;
	STRINT(data, 28) = *(int*)&dataStruct->y;
	STRINT(data, 32) = *(int*)&dataStruct->XSpeed;
	STRINT(data, 36) = *(int*)&dataStruct->YSpeed;
	STRINT(data, 44) = dataStruct->punchX;
	STRINT(data, 48) = dataStruct->punchY;
	return data;
}

/*void sendApplyLock(ENetPeer* _peer, int x, int y, int id, int locksize) {
    Player* player = (Player*)(_peer->data);
    World* world = player->currentWorld;

    PlayerMoving pmov;
    pmov.packetType = 15;
    pmov.characterState = 0;
    pmov.x = 0;
    pmov.y = 0;
    pmov.XSpeed = 0;
    pmov.YSpeed = 0;
    pmov.plantingTree = id;
    pmov.punchX = x;
    pmov.punchY = y;
    pmov.netID = player->userid;

    string packetstr;
    packetstr.resize(4);
    packetstr[0] = 4;
    packetstr += packPlayerMoving(&pmov);
    packetstr[12] = locksize;
    packetstr[16] = 8;
    STRINT(packetstr, 52+4) = locksize * 2;
    packetstr.resize(packetstr.length() + locksize * 2);

    for (uint32_t i = 0; i < locksize; i++) {
        STR16(packetstr, 56 + 4 + i * 2) = y * 100 + x - i;
    }

    ENetPacket* packet = enet_packet_create(&packetstr[0],
        packetstr.length(),
        ENET_PACKET_FLAG_RELIABLE);

    for (ENetPeer* peer = server->peers; peer < &server->peers[server->peerCount]; ++peer) {
        if (peer->state != ENET_PEER_STATE_CONNECTED) continue;
        Player* loopPlayer = (Player*)(peer->data);

        if (loopPlayer->currentWorld != NULL && loopPlayer->currentWorld == player->currentWorld) {
            enet_peer_send(peer, 0, packet);
            SendPlayPositioned(peer, "audio/use_lock.wav");
        }
    }
}*/

std::string get_right_of_delim(std::string const& str, std::string const& delim) {
	return str.substr(str.find(delim) + delim.size());
}

void Player::OnPlayPositioned(ENetPeer * peer, string audiofile, int netID, bool broadcastInWorld, ENetPacket* pk) // packet only externally used when broadcasting / sending to multiple players to reduce memory leaks / cpu usage cuz we dont want to loop creating the packet for each player that would be insanely stupid.
{
	if (broadcastInWorld) {		
		ENetPeer * currentPeer;

		for (currentPeer = server->peers;
			currentPeer < &server->peers[server->peerCount];
			++currentPeer)
		{
			if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
				continue;		
			if (isHere(peer, currentPeer)) {
				enet_peer_send(currentPeer, 0, pk);
			}
		}
	}
	else
	{
		auto p = packetEnd(appendString(appendString(createPacket(), "OnPlayPositioned"), audiofile));
		memcpy(p.data + 8, &netID, 4);
		ENetPacket* packet = enet_packet_create(p.data,
			p.len,
			ENET_PACKET_FLAG_RELIABLE);
		enet_peer_send(peer, 0, packet);
		delete p.data;
	}
}

BYTE* packStuffVisual(TileExtra* dataStruct, int options, int gravity)
{
	BYTE* data = new BYTE[102];
	for (int i = 0; i < 102; i++)
	{
		data[i] = 0;
	}
	memcpy(data, &dataStruct->packetType, 4);
	memcpy(data + 8, &dataStruct->netID, 4);
	memcpy(data + 12, &dataStruct->characterState, 4);
	//memcpy(data + 40, &dataStruct->bpm, 4);
	memcpy(data + 44, &dataStruct->punchX, 4);
	memcpy(data + 48, &dataStruct->punchY, 4);
	memcpy(data + 52, &dataStruct->charStat, 4);
	memcpy(data + 56, &dataStruct->blockid, 2);
	memcpy(data + 58, &dataStruct->backgroundid, 2);
	memcpy(data + 60, &dataStruct->visual, 4);
	memcpy(data + 64, &dataStruct->displayblock, 4);
	memcpy(data + 68, &gravity, 4);
	memcpy(data + 70, &options, 4);

	return data;
}

void addInventoryItem(ENetPeer* peer, int id, int netID, int amount) {
	PlayerMoving pmov;
	memset(&pmov, 0, sizeof(PlayerMoving));
	pmov.netID = netID;
	pmov.plantingTree = id;
	pmov.packetType = 13;
	string packet;
	packet.resize(4);
	packet[0] = 4;
	packet += packPlayerMoving2(&pmov);
	packet[4 + 3] = amount;
	ENetPacket* epacket = enet_packet_create(&packet[0],
		packet.length(),
		ENET_PACKET_FLAG_RELIABLE);
	enet_peer_send(peer, 0, epacket);
}

void removeInventoryItem(ENetPeer* peer, int id, int amount) {

	PlayerMoving pmov;
	pmov.netID = -1;
	pmov.plantingTree = id;
	pmov.packetType = 13;
	string packet;
	packet.resize(4);
	packet[0] = 4;
	packet += packPlayerMoving2(&pmov);
	packet[4 + 2] = amount;
	ENetPacket* epacket = enet_packet_create(&packet[0],
		packet.length(),
		ENET_PACKET_FLAG_RELIABLE);
	enet_peer_send(peer, 0, epacket);
}

void SendPacketRaw2(int a1, void *packetData, size_t packetDataSize, void *a4, ENetPeer* peer, int packetFlag)
{
	ENetPacket *p;

	if (peer) // check if we have it setup
	{
		if (a1 == 4 && *((BYTE *)packetData + 12) & 8)
		{
			p = enet_packet_create(0, packetDataSize + *((DWORD *)packetData + 13) + 5, packetFlag);
			int four = 4;
			memcpy(p->data, &four, 4);
			memcpy((char *)p->data + 4, packetData, packetDataSize);
			memcpy((char *)p->data + packetDataSize + 4, a4, *((DWORD *)packetData + 13));
			enet_peer_send(peer, 0, p);

		}
		else
		{
			if (a1 == 192) {
				a1 = 4;
				p = enet_packet_create(0, packetDataSize + 5, packetFlag);
				memcpy(p->data, &a1, 4);
				memcpy((char *)p->data + 4, packetData, packetDataSize);
				enet_peer_send(peer, 0, p);


			}
			else {
				p = enet_packet_create(0, packetDataSize + 5, packetFlag);
				memcpy(p->data, &a1, 4);
				memcpy((char *)p->data + 4, packetData, packetDataSize);
				enet_peer_send(peer, 0, p);


			}
		}
	}

	delete packetData;
}




void sendCollect(ENetPeer* peer, int netID, int x, int y, int uid)
{
	if (uid >= 9999) return;
	if (uid < 0) return;
	ENetPeer * currentPeer;
	string name = "";
	for (currentPeer = server->peers;
		currentPeer < &server->peers[server->peerCount];
		++currentPeer)
	{
		if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
			continue;
		if (isHere(peer, currentPeer)) {
			PlayerMoving data;
			data.packetType = 14;
			data.x = x;
			data.y = y;
			data.netID = netID;
			data.plantingTree = uid;		
			SendPacketRaw(4, packPlayerMoving(&data), 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
		}
	}
}





void sendShop(ENetPeer* peer) {
	GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|\nadd_label_with_ele_icon|big|`wGTV3 Shop|left|5956|\nadd_label_with_icon|small|`9Custom items``|left|1790|\n\nadd_button_with_icon|estocape||staticBlueFrame|9140|2|Estonian Cape|\nadd_quick_exit|\nnend_dialog|gazette||OK|"));
	ENetPacket * packet = enet_packet_create(p.data,
		p.len,
		ENET_PACKET_FLAG_RELIABLE);
	enet_peer_send(peer, 0, packet);
	delete p.data;
}

void updateStuffWeather(ENetPeer* peer, int x, int y, int tile, int bg, int gravity, bool isInverted, bool isSpinning) {
	
	
	ENetPeer * currentPeer;
	for (currentPeer = server->peers;
		currentPeer < &server->peers[server->peerCount];
		++currentPeer)
	{
		if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
			continue;
		if (isHere(peer, currentPeer)) {




			//cout << "bruh" << endl;
			TileExtra data;
			data.packetType = 0x5;
			data.characterState = 8;
			data.punchX = x;
			data.punchY = y;
			data.charStat = 18; // 13
			data.blockid = 3832;
			data.backgroundid = bg; // 2946
								   //data.netID = ((PlayerInfo)(peer->data))->netID;
								   //dataxx.backgroundid = 65536;
			data.visual = 0; //0x00210000
										//world->items[x + (yworld->width)].displayblock = tile;
			int n = tile;
			string hex = "";
			{
				std::stringstream ss;
				ss << std::hex << n; // int decimal_value
				std::string res(ss.str());
				hex = res + "31";
			}
			int gravi = gravity;
			string hexg = "";
			{
				int temp = gravi;
				if (gravi < 0) temp = -gravi;
				std::stringstream ss;
				ss << std::hex << temp; // int decimal_value
				std::string res(ss.str());
				hexg = res + "00";
			}
			int xx = 0;
			std::stringstream ss;
			ss << std::hex << hex;
			if (!ss.fail()) {
				ss >> xx;
			}
			//cout << xx << endl;
			data.displayblock = xx;
			int xxs = 0;
			std::stringstream sss;
			sss << std::hex << hexg;
			if (!sss.fail()) {
				sss >> xxs;
			}
			if (gravi < 0) xxs = -xxs;
			//cout << to_string(xxs) << endl;
			if (gravi < 0) {
				SendPacketRaw2(192, packStuffVisual(&data, 0x03FFFFFF, xxs), 102, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
			}
			else
			{
				SendPacketRaw2(192, packStuffVisual(&data, 0x02000000, xxs), 102, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
			}
			GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnSetCurrentWeather"), 29));
			ENetPacket* packet2 = enet_packet_create(p2.data,
				p2.len,
				ENET_PACKET_FLAG_RELIABLE);

			enet_peer_send(currentPeer, 0, packet2);
			delete p2.data;
		}
	}
}

inline uint32_t getUserId(const std::string& str) {

	uint32_t hash = 0x811c9dc5;
	uint32_t prime = 0x1000193;

	for (int i = 0; i < str.size(); ++i) {
		uint8_t value = str[i];
		hash = hash ^ value;
		hash *= prime;
	}

	return hash;

}

void sendPData(ENetPeer* peer, PlayerMoving* data)
{
	ENetPeer * currentPeer;

	for (currentPeer = server->peers;
		currentPeer < &server->peers[server->peerCount];
		++currentPeer)
	{
		if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
			continue;
		if (peer != currentPeer)
		{
			if (isHere(peer, currentPeer))
			{
				data->netID = ((PlayerInfo*)(peer->data))->netID;

				SendPacketRaw(4, packPlayerMoving(data), 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
			}
		}
	}
}

int getState(PlayerInfo* info) {
	int val = 0;
	val |= info->canWalkInBlocks << 0;
	val |= info->canDoubleJump << 1;
	val |= info->isInvisible << 2;
	val |= info->noHands << 3;
	val |= info->noEyes << 4;
	val |= info->noBody << 5;
	val |= info->devilHorns << 6;
	val |= info->goldenHalo << 7;
	val |= info->isFrozen << 8;
	val |= info->isCursed << 12;
	val |= info->isDuctaped << 13;
	val |= info->haveCigar << 14;
	val |= info->isShining << 15;
	val |= info->isZombie << 16;
	val |= info->isHitByLava << 17;
	val |= info->haveHauntedShadows << 18;
	val |= info->haveGeigerRadiation << 19;
	val |= info->haveReflector << 20;
	val |= info->isEgged << 21;
	val |= info->havePineappleFloag << 22;
	val |= info->haveFlyingPineapple << 23;
	val |= info->haveSuperSupporterName << 24;
	val |= info->haveSupperPineapple << 25;
	return val;
}

void sendState(ENetPeer* peer, PlayerInfo* info) {
	//return; // TODO
	int netID = info->netID;
	ENetPeer * currentPeer;
	int state = getState(info);
	for (currentPeer = server->peers;
		currentPeer < &server->peers[server->peerCount];
		++currentPeer)
	{
		if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
			continue;
		if (isHere(peer, currentPeer)) {
			PlayerMoving data;
			float water = 125.0f;
			data.packetType = 0x14;
			data.characterState = 0; // animation
			data.x = 1000;
			if (((PlayerInfo*)(peer->data))->cloth_hand == 366) {
				data.y = -400; // - is hbow
			}
			else {
				data.y = 400;
			}
			data.punchX = 0;
			data.punchY = 0;
			data.XSpeed = 300;
			data.YSpeed = 1150;
			data.netID = netID;
			data.plantingTree = state;
			BYTE* raw = packPlayerMoving(&data);
			int var = 0x818100; // placing and breking 0x808040 
			memcpy(raw + 1, &var, 3);
			memcpy(raw + 16, &water, 4);
			SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
		}
	}
	// TODO
}

void updateAllClothes(ENetPeer* peer)
{
	ENetPeer * currentPeer;
	for (currentPeer = server->peers;
		currentPeer < &server->peers[server->peerCount];
		++currentPeer)
	{
		if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
			continue;
		if (isHere(peer, currentPeer))
		{
			GamePacket p3 = packetEnd(appendFloat(appendIntx(appendFloat(appendFloat(appendFloat(appendString(createPacket(), "OnSetClothing"), ((PlayerInfo*)(peer->data))->cloth_hair, ((PlayerInfo*)(peer->data))->cloth_shirt, ((PlayerInfo*)(peer->data))->cloth_pants), ((PlayerInfo*)(peer->data))->cloth_feet, ((PlayerInfo*)(peer->data))->cloth_face, ((PlayerInfo*)(peer->data))->cloth_hand), ((PlayerInfo*)(peer->data))->cloth_back, ((PlayerInfo*)(peer->data))->cloth_mask, ((PlayerInfo*)(peer->data))->cloth_necklace), ((PlayerInfo*)(peer->data))->skinColor), ((PlayerInfo*)(peer->data))->cloth_ances, 0.0f, 0.0f));
			memcpy(p3.data + 8, &(((PlayerInfo*)(peer->data))->netID), 4); // ffloor
			ENetPacket * packet3 = enet_packet_create(p3.data,
				p3.len,
				ENET_PACKET_FLAG_RELIABLE);

			enet_peer_send(currentPeer, 0, packet3);
			delete p3.data;
			//enet_host_flush(server);
			GamePacket p4 = packetEnd(appendFloat(appendIntx(appendFloat(appendFloat(appendFloat(appendString(createPacket(), "OnSetClothing"), ((PlayerInfo*)(currentPeer->data))->cloth_hair, ((PlayerInfo*)(currentPeer->data))->cloth_shirt, ((PlayerInfo*)(currentPeer->data))->cloth_pants), ((PlayerInfo*)(currentPeer->data))->cloth_feet, ((PlayerInfo*)(currentPeer->data))->cloth_face, ((PlayerInfo*)(currentPeer->data))->cloth_hand), ((PlayerInfo*)(currentPeer->data))->cloth_back, ((PlayerInfo*)(currentPeer->data))->cloth_mask, ((PlayerInfo*)(currentPeer->data))->cloth_necklace), ((PlayerInfo*)(currentPeer->data))->skinColor), ((PlayerInfo*)(currentPeer->data))->cloth_ances, 0.0f, 0.0f));
			memcpy(p4.data + 8, &(((PlayerInfo*)(currentPeer->data))->netID), 4); // ffloor
			ENetPacket * packet4 = enet_packet_create(p4.data,
				p4.len,
				ENET_PACKET_FLAG_RELIABLE);
			enet_peer_send(peer, 0, packet4);
			delete p4.data;

			sendState(peer, ((PlayerInfo*)(currentPeer->data)));
			//enet_host_flush(server);
		}
	}
}

void sendRoulete(ENetPeer* peer, int x, int y)
{
	ENetPeer* currentPeer;
	int val = rand() % 37;
	for (currentPeer = server->peers;
		currentPeer < &server->peers[server->peerCount];
		++currentPeer)
	{
		if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
			continue;
		if (isHere(peer, currentPeer))
		{
			GamePacket p2 = packetEnd(appendIntx(appendString(appendIntx(appendString(createPacket(), "OnTalkBubble"), ((PlayerInfo*)(peer->data))->netID), "`w[" + ((PlayerInfo*)(peer->data))->displayName + " `wspun the wheel and got `6" + std::to_string(val) + "`w!]"), 0));
			int respawnTimeout = 2000;
			int deathFlag = 0x19;
			memcpy(p2.data + 24, &respawnTimeout, 4);
			memcpy(p2.data + 56, &deathFlag, 4);
			ENetPacket * packet2 = enet_packet_create(p2.data,
				p2.len,
				ENET_PACKET_FLAG_RELIABLE);			
			enet_peer_send(currentPeer, 0, packet2);			
			delete p2.data;
		}


		//cout << "Tile update at: " << data2->punchX << "x" << data2->punchY << endl;
	}
}

void sendClothes(ENetPeer* peer)
{
	ENetPeer * currentPeer;
	GamePacket p3 = packetEnd(appendFloat(appendIntx(appendFloat(appendFloat(appendFloat(appendString(createPacket(), "OnSetClothing"), ((PlayerInfo*)(peer->data))->cloth_hair, ((PlayerInfo*)(peer->data))->cloth_shirt, ((PlayerInfo*)(peer->data))->cloth_pants), ((PlayerInfo*)(peer->data))->cloth_feet, ((PlayerInfo*)(peer->data))->cloth_face, ((PlayerInfo*)(peer->data))->cloth_hand), ((PlayerInfo*)(peer->data))->cloth_back, ((PlayerInfo*)(peer->data))->cloth_mask, ((PlayerInfo*)(peer->data))->cloth_necklace), ((PlayerInfo*)(peer->data))->skinColor), ((PlayerInfo*)(peer->data))->cloth_ances, 0.0f, 0.0f));
	for (currentPeer = server->peers;
		currentPeer < &server->peers[server->peerCount];
		++currentPeer)
	{
		if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
			continue;
		if (isHere(peer, currentPeer))
		{

			memcpy(p3.data + 8, &(((PlayerInfo*)(peer->data))->netID), 4); // ffloor
			ENetPacket * packet3 = enet_packet_create(p3.data,
				p3.len,
				ENET_PACKET_FLAG_RELIABLE);

			enet_peer_send(currentPeer, 0, packet3);
		}

	}
	delete p3.data;
	
}

void SendTradeEffect(ENetPeer* peer, int id, int netIDsrc, int netIDdst, int timeMs)
{
	PlayerMoving data;
	data.packetType = 0x13;
	data.punchX = id;
	data.punchY = id;

	BYTE* raw = packPlayerMoving(&data);
	int netIdSrc = netIDsrc;
	int netIdDst = netIDdst;
	int three = 3;
	int n1 = timeMs;
	memcpy(raw + 3, &three, 1);
	memcpy(raw + 4, &netIdDst, 4);
	memcpy(raw + 8, &netIdSrc, 4);
	memcpy(raw + 20, &n1, 4);

	ENetPeer * currentPeer;
	for (currentPeer = server->peers;
		currentPeer < &server->peers[server->peerCount];
		++currentPeer)
	{
		if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
			continue;
		if (isHere(peer, currentPeer))
		{
			BYTE* raw2 = new BYTE[56];
			memcpy(raw2, raw, 56);
			SendPacketRaw(4, raw2, 56, 0, peer, ENET_PACKET_FLAG_RELIABLE);
		}
	}
	delete raw;
}

void updateProviderVisuals(ENetPeer* peer, int foreground, int x, int y, int background, int timeIntoGrowth, bool forEveryone, int blockStateFlags) {
	//int val = 1 + rand() % 4;

	int hmm = 8;
	int zero = 0;
	int packetType = 5;
	int yeh = hmm + 3 + 1;
	int idk = 15 + 4;
	int blockState = blockStateFlags;
	int bubble_type = 9;
	int ok = 52 + idk;
	int packetSize = ok + 4;
	int yup = ok - 8 - idk;
	int four = 4;
	int magic = 56;
	int wew = ok + 5 + 4;
	int wow = magic + 4 + 5;

	int time = (int)timeIntoGrowth;
	int text_len = 4;
	int treedata = 0x00020000;
	blockState |= 0x100000;

	BYTE* data = new BYTE[packetSize];
	ENetPacket* p = enet_packet_create(0, wew, ENET_PACKET_FLAG_RELIABLE);
	memset(data, 0, packetSize);

	memcpy(data, &packetType, sizeof(int));
	memcpy(data + yeh, &hmm, sizeof(int));
	memcpy(data + yup, &x, sizeof(int));
	memcpy(data + yup + 4, &y, sizeof(int));
	memcpy(data + 4 + yup + 4, &idk, sizeof(int));
	// here is where tile serialization actually starts
	// it's literally the same as in worldptr i think
	// :)
	memcpy(data + magic, &foreground, sizeof(short));
	memcpy(data + magic + 2, &background, sizeof(short));
	memcpy(data + magic + 4, &blockState, sizeof(int));
	memcpy(data + magic + 8, &bubble_type, sizeof(byte));

	memcpy(data + magic + 9 + 0, &time, 4);

	memcpy(data + ok, &blockState, sizeof(int));
	memcpy(p->data, &four, four);

	memcpy((char*)p->data + four, data, packetSize);
	if (forEveryone)
	{
		ENetPeer* currentPeer;
		for (currentPeer = server->peers;
			currentPeer < &server->peers[server->peerCount];
			++currentPeer)
		{
			if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
				continue;
			if (isHere(peer, currentPeer)) {
				enet_peer_send(currentPeer, 0, p);
			}
		}
		delete data;
	}
	else
	{
		enet_peer_send(peer, 0, p);
		delete data;
	}
}

void updateTreeVisuals(ENetPeer* peer, int foreground, int x, int y, int background, int fruitCount, int timeIntoGrowth, bool forEveryone, int blockStateFlags) {
	//int val = 1 + rand() % 4;

	int hmm = 8;
	int zero = 0;
	int packetType = 5;
	int yeh = hmm + 3 + 1;
	int idk = 15 + 4;
	int blockState = blockStateFlags;
	int bubble_type = 4;
	int ok = 52 + idk;
	int packetSize = ok + 4;
	int yup = ok - 8 - idk;
	int four = 4;
	int magic = 56;
	int wew = ok + 5 + 4;
	int wow = magic + 4 + 5;

	short fc = (short)fruitCount;
	int time = (int)timeIntoGrowth;
	int text_len = 4;
	int treedata = 0x00020000;
	blockState |= 0x100000;

	BYTE* data = new BYTE[packetSize];
	ENetPacket* p = enet_packet_create(0, wew, ENET_PACKET_FLAG_RELIABLE);
	memset(data, 0, packetSize);

	memcpy(data, &packetType, sizeof(int));
	memcpy(data + yeh, &hmm, sizeof(int));
	memcpy(data + yup, &x, sizeof(int));
	memcpy(data + yup + 4, &y, sizeof(int));
	memcpy(data + 4 + yup + 4, &idk, sizeof(int));
	// here is where tile serialization actually starts
	// it's literally the same as in worldptr i think
	// :)
	memcpy(data + magic, &foreground, sizeof(short));
	memcpy(data + magic + 2, &background, sizeof(short));
	memcpy(data + magic + 4, &blockState, sizeof(int));
	memcpy(data + magic + 8, &bubble_type, sizeof(byte));

	memcpy(data + magic + 9 + 0, &time, 4);
	memcpy(data + magic + 9 + 4, &fc, 1);

	memcpy(data + ok, &blockState, sizeof(int));
	memcpy(p->data, &four, four);

	memcpy((char*)p->data + four, data, packetSize);
	if (forEveryone)
	{
		ENetPeer* currentPeer;
		for (currentPeer = server->peers;
			currentPeer < &server->peers[server->peerCount];
			++currentPeer)
		{
			if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
				continue;
			if (isHere(peer, currentPeer)) {
				enet_peer_send(currentPeer, 0, p);
			}
		}
		delete data;
	}
	else
	{
		enet_peer_send(peer, 0, p);
		delete data;
	}
}

void clearWorld(ENetPeer* peer, int x, int y) {
	TileExtra data;
	data.packetType = 0x5;
	data.characterState = 8;
	data.punchX = x;
	data.punchY = y;
	data.charStat = 8;
	data.blockid = 0;
	data.backgroundid = 0;
	data.visual = 0x0010000;
	SendPacketRaw2(192, packBlockVisual(&data), 102, 0, peer, ENET_PACKET_FLAG_RELIABLE);
}

void updateDoor(ENetPeer* peer, int background, int foreground, int x, int y, string text)
{
	PlayerMoving sign;
	sign.packetType = 0x3;
	sign.characterState = 0x0;
	sign.x = x;
	sign.y = y;
	sign.punchX = x;
	sign.punchY = y;
	sign.XSpeed = 0;
	sign.YSpeed = 0;
	sign.netID = -1;
	sign.plantingTree = foreground;
	SendPacketRaw(4, packPlayerMoving(&sign), 56, 0, peer, ENET_PACKET_FLAG_RELIABLE);

	int hmm = 8;
	int text_len = text.length();
	int lol = 0;
	int wut = 5;
	int yeh = hmm + 3 + 1;
	int idk = 15 + text_len;
	int is_locked = 0;
	int bubble_type = 1;
	int ok = 52 + idk;
	int kek = ok + 4;
	int yup = ok - 8 - idk;
	int four = 4;
	int magic = 56;
	int wew = ok + 5 + 4;
	int wow = magic + 4 + 5;

	BYTE* data = new BYTE[kek];
	ENetPacket* p = enet_packet_create(0, wew, ENET_PACKET_FLAG_RELIABLE);
	for (int i = 0; i < kek; i++) data[i] = 0;
	memcpy(data, &wut, four);
	memcpy(data + yeh, &hmm, four);
	memcpy(data + yup, &x, 4);
	memcpy(data + yup + 4, &y, 4);
	memcpy(data + 4 + yup + 4, &idk, four);
	memcpy(data + magic, &foreground, 2);
	memcpy(data + magic + 2, &background, 2);
	memcpy(data + four + magic, &lol, four);
	memcpy(data + magic + 4 + four, &bubble_type, 1);
	memcpy(data + wow, &text_len, 2);
	memcpy(data + 2 + wow, text.c_str(), text_len);
	memcpy(data + ok, &is_locked, four);
	memcpy(p->data, &four, four);
	memcpy((char*)p->data + four, data, kek);
	enet_peer_send(peer, 0, p);
	delete data;
}

void updateSign(ENetPeer* peer, int foreground, int background, int x, int y, string text)
{
	/*PlayerMoving sign;
	sign.packetType = 0x3;
	sign.characterState = 0x0;
	sign.x = x;
	sign.y = y;
	sign.punchX = x;
	sign.punchY = y;
	sign.XSpeed = 0;
	sign.YSpeed = 0;
	sign.netID = -1;
	sign.plantingTree = foreground;
	SendPacketRaw(4, packPlayerMoving(&sign), 56, 0, peer, ENET_PACKET_FLAG_RELIABLE);*/

	int hmm = 8;
	int text_len = text.length();
	int lol = 0;
	int wut = 5;
	int yeh = hmm + 3 + 1;
	int idk = 15 + text_len;
	int is_locked = 0;
	int bubble_type = 2;
	int ok = 52 + idk;
	int kek = ok + 4;
	int yup = ok - 8 - idk;
	int four = 4;
	int magic = 56;
	int wew = ok + 5 + 4;
	int wow = magic + 4 + 5;

	BYTE* data = new BYTE[kek];
	ENetPacket* p = enet_packet_create(0, wew, ENET_PACKET_FLAG_RELIABLE);
	for (int i = 0; i < kek; i++) data[i] = 0;
	memcpy(data, &wut, four);
	memcpy(data + yeh, &hmm, four);
	memcpy(data + yup, &x, 4);
	memcpy(data + yup + 4, &y, 4);
	memcpy(data + 4 + yup + 4, &idk, four);
	memcpy(data + magic, &foreground, 2);
	memcpy(data + magic + 2, &background, 2);
	memcpy(data + four + magic, &lol, four);
	memcpy(data + magic + 4 + four, &bubble_type, 1);
	memcpy(data + wow, &text_len, 2);
	memcpy(data + 2 + wow, text.c_str(), text_len);
	memcpy(data + ok, &is_locked, four);
	memcpy(p->data, &four, four);
	memcpy((char*)p->data + four, data, kek);
	enet_peer_send(peer, 0, p);
	delete data;
}

void Player::OnBillboardChange(ENetPeer* peer, int netID) {

	GamePacket p = packetEnd(appendInt(appendInt(appendInt(appendInt(appendIntx(appendString(createPacket(), "OnBillboardChange"), 1 /*???*/), 12), 1), 5), 1)); //2 == ItemID
	memcpy(p.data + 8, &netID, 4);
	ENetPacket* packet = enet_packet_create(p.data,
		p.len,
		ENET_PACKET_FLAG_RELIABLE);

	enet_peer_send(peer, 0, packet);
	delete p.data;
}

void Player::OnFlagMay2019(ENetPeer* peer, int state, int netID) {
	GamePacket p = packetEnd(appendIntx(appendString(createPacket(), "OnFlagMay2019"), state));		
	memcpy(p.data + 8, &netID, 4);
	ENetPacket * packet = enet_packet_create(p.data,
		p.len,
		ENET_PACKET_FLAG_RELIABLE);
	enet_peer_send(peer, 0, packet);
	delete p.data;
}

void Player::OnStartTrade(ENetPeer * peer, int netID1, int netID2)
{
	GamePacket p = packetEnd(appendInt(appendInt(appendString(createPacket(), "OnStartTrade"), netID1), netID2));
	ENetPacket * packet = enet_packet_create(p.data,
		p.len,
		ENET_PACKET_FLAG_RELIABLE);
	enet_peer_send(peer, 0, packet);
	delete p.data;
}

void Player::OnForceTradeEnd(ENetPeer * peer)
{
	GamePacket p = packetEnd(appendString(createPacket(), "OnForceTradeEnd"));
	ENetPacket * packet = enet_packet_create(p.data,
		p.len,
		ENET_PACKET_FLAG_RELIABLE);
	enet_peer_send(peer, 0, packet);
	delete p.data;
}

void Player::PlayAudio(ENetPeer * peer, string audioFile, int delayMS)
{
	string text = "action|play_sfx\nfile|" + audioFile + "\ndelayMS|" + to_string(delayMS) + "\n";
	BYTE* data = new BYTE[5 + text.length()];
	BYTE zero = 0;
	int type = 3;
	memcpy(data, &type, 4);
	memcpy(data + 4, text.c_str(), text.length());
	memcpy(data + 4 + text.length(), &zero, 1);
	ENetPacket * packet = enet_packet_create(data,
		5 + text.length(),
		ENET_PACKET_FLAG_RELIABLE);

	enet_peer_send(peer, 0, packet);
	delete data;
}

void Player::showWrong(ENetPeer* peer, string itemFind, string listFull) {

	GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "add_label_with_icon|big|`wFind item: " + itemFind + "``|left|206|\nadd_spacer|small|\n" + listFull + "add_textbox|Enter a word below to find the item|\nadd_text_input|item|Item Name||30|\nend_dialog|findid|Cancel|Find the item!|\n"));
	ENetPacket* packet = enet_packet_create(p.data,
		p.len,
		ENET_PACKET_FLAG_RELIABLE);
	enet_peer_send(peer, 0, packet);
	delete p.data;
}

void InitializePacketWithMannequin(BYTE* raw)
{
	int i = 0;
	raw[i] = 0x05; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x08; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x09; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x17; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x22; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x8c; i++;
	raw[i] = 0x05; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x01; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x0e; i++;
	raw[i] = 0x00; i++; 
	raw[i] = 0x00; i++;
	raw[i] = 0x00; i++;
}


void updateMannequin(
	ENetPeer* peer, int foreground, int x, int y, int background, string text,
	int clothHair, int clothHead, int clothMask,
	int clothHand, int clothNeck, int clothShirt,
	int clothPants, int clothFeet, int clothBack, bool sendPacketToEveryone = true, int blockState = 0)
{
	PlayerMoving sign;
	sign.packetType = 0x3;
	sign.characterState = 0x0;
	sign.x = x;
	sign.y = y;
	sign.punchX = x;
	sign.punchY = y;
	sign.XSpeed = 0;
	sign.YSpeed = 0;
	sign.netID = -1;
	sign.plantingTree = foreground;
	SendPacketRaw(4, packPlayerMoving(&sign), 56, 0, peer, ENET_PACKET_FLAG_RELIABLE);

	short textLen = text.size();
	int plength = 95 + textLen;
	BYTE* raw = new BYTE[plength];
	memset(raw, 0, plength);
	InitializePacketWithMannequin(raw);
	int negativeOne = -1;
	int adjhasdjk = 0xfdfdfdfd;
	int visor = 138;

	memcpy(raw + 44, &x, sizeof(int));
	memcpy(raw + 48, &y, sizeof(int));
	memcpy(raw + 56, &foreground, sizeof(short));
	memcpy(raw + 58, &background, sizeof(short));
	memcpy(raw + 60, &blockState, sizeof(short));
	memcpy(raw + 65, &textLen, sizeof(short));
	memcpy(raw + 67, text.c_str(), textLen);
	memcpy(raw + 68 + textLen, &negativeOne, sizeof(int));	
	memcpy(raw + 72 + textLen, &clothHead, sizeof(short));
	memcpy(raw + 74 + textLen, &clothShirt, sizeof(short));
	memcpy(raw + 76 + textLen, &clothPants, sizeof(short));
	memcpy(raw + 78 + textLen, &clothFeet, sizeof(short));
	memcpy(raw + 80 + textLen, &clothMask, sizeof(short));
	memcpy(raw + 82 + textLen, &clothHand, sizeof(short));
	memcpy(raw + 84 + textLen, &clothBack, sizeof(short));
	memcpy(raw + 86 + textLen, &clothHair, sizeof(short));
	memcpy(raw + 88 + textLen, &clothNeck, sizeof(short));
	memcpy(raw + 91 + textLen, &adjhasdjk, sizeof(short));

	ENetPacket* p = enet_packet_create(0, plength + 4, ENET_PACKET_FLAG_RELIABLE);
	int four = 4;
	memcpy(p->data, &four, sizeof(int));
	memcpy((char*)p->data + 4, raw, plength);

	if (sendPacketToEveryone)
	{
		ENetPeer* currentPeer;
		for (currentPeer = server->peers;
			currentPeer < &server->peers[server->peerCount];
			++currentPeer)
		{
			if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
				continue;
			if (isHere(peer, currentPeer)) {
				enet_peer_send(currentPeer, 0, p);
			}
		}
		delete raw;
	}
	else
	{
		enet_peer_send(peer, 0, p);
		delete raw;
	}
}

int getPlayersCountInWorld(string name)
{
	int count = 0;
	ENetPeer * currentPeer;
	for (currentPeer = server->peers;
		currentPeer < &server->peers[server->peerCount];
		++currentPeer)
	{
		if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
			continue;
		if (((PlayerInfo*)(currentPeer->data))->currentWorld == name)
			if (((PlayerInfo*)(currentPeer->data))->isinv == false) count++;				
	}
	return count;
}

void Player::SendTilePickup(ENetPeer* peer, int itemid, int netID, float x, float y, int itemcount, int itemamount) {
	PlayerMoving data;
	data.characterState = 0x0; // animation
	data.x = x * 32;
	data.y = y * 32;
	data.punchX = 0;
	data.punchY = 0;
	data.XSpeed = 0;
	data.YSpeed = 0;
	data.netID = -1;
	data.secondnetID = -1;
	data.plantingTree = itemid;
	data.packetType = 0xE;
	BYTE* raw = packPlayerMoving(&data);
	int netIdSrc = -1;
	int netIdDst = -1;
	int three = 3;
	int n1 = itemid;
	int one = 1;
	float count = itemamount;
	memcpy(raw + 3, &three, 1);
	memcpy(raw + 4, &netIdDst, 4);
	memcpy(raw + 8, &netIdSrc, 4);
	memcpy(raw + 16, &count, 4);
	memcpy(raw + 20, &n1, 4);
	
	((PlayerInfo*)(peer->data))->droppeditemcount++;
	SendPacketRaw(4, raw, 56, 0, peer, ENET_PACKET_FLAG_RELIABLE);	

	PlayerMoving datax;
	datax.characterState = 0x0; // animation
	datax.x = x * 32;
	datax.y = y * 32;
	datax.punchX = 0;
	datax.punchY = 0;
	datax.XSpeed = 0;
	datax.YSpeed = 0;
	datax.netID = -1;
	datax.secondnetID = 0;
	datax.plantingTree = itemid;
	datax.packetType = 0xE;
	BYTE* raws = packPlayerMoving(&data);
	int lol = -1;
	
	
	memcpy(raws + 3, &three, 1);
	memcpy(raws + 4, &netID, 4);
	memcpy(raws + 8, &lol, 4);
	memcpy(raws + 20, &((PlayerInfo*)(peer->data))->droppeditemcount, 4);
	SendPacketRaw(4, raws, 56, 0, peer, ENET_PACKET_FLAG_RELIABLE);
}

void Player::SendTileAnimation(ENetPeer * peer, int x, int y, int causedBy, int tile)
{
	if (x > -1 && y > -1 && causedBy > -1)
	{
		PlayerMoving data;
		data.characterState = 0x0; // animation
		data.x = x;
		data.y = y;
		data.punchX = 0;
		data.punchY = 0;
		data.XSpeed = 0;
		data.YSpeed = 0;
		data.netID = causedBy;
		data.plantingTree = 6;
		data.packetType = 0x8;
		SendPacketRaw(4, packPlayerMoving(&data), 56, 0, peer, ENET_PACKET_FLAG_RELIABLE);
	}
}

void Player::OnStartAcceptLogon(ENetPeer* peer, int itemdathash) {
	GamePacket p = packetEnd(appendString(appendString(appendString(appendString(appendInt(appendString(createPacket(),
		"OnSuperMainStartAcceptLogonHrdxs47254722215a"), itemdathash),"growtopia3.com"), "a/cache/"),
		"cc.cz.madkite.freedom org.aqua.gg idv.aqua.bulldog com.cih.gamecih2 com.cih.gamecih com.cih.game_cih cn.maocai.gamekiller com.gmd.speedtime org.dax.attack com.x0.strai.frep com.x0.strai.free org.cheatengine.cegui org.sbtools.gamehack com.skgames.traffikrider org.sbtoods.gamehaca com.skype.ralder org.cheatengine.cegui.xx.multi1458919170111 com.prohiro.macro me.autotouch.autotouch com.cygery.repetitouch.free com.cygery.repetitouch.pro com.proziro.zacro com.slash.gamebuster"),
		"proto=80|choosemusic=audio/mp3/theme4.mp3|active_holiday=0|"));

	ENetPacket * packet = enet_packet_create(p.data,
		p.len,
		ENET_PACKET_FLAG_RELIABLE);
	enet_peer_send(peer, 0, packet);
	delete p.data;
}

void Player::OnRemove(ENetPeer * peer, int netID)
{
	GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnRemove"), "netID|" + std::to_string(netID) + "\n"));
	ENetPacket * packet = enet_packet_create(p.data,
		p.len,
		ENET_PACKET_FLAG_RELIABLE);
	enet_peer_send(peer, 0, packet);
	delete p.data;
}

void Player::OnConsoleMessage(ENetPeer * peer, string text)
{
	GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), text));
	ENetPacket * packet = enet_packet_create(p.data,
		p.len,
		ENET_PACKET_FLAG_RELIABLE);
	enet_peer_send(peer, 0, packet);
	delete p.data;
}

void Player::OnTalkBubble(ENetPeer * peer, int netID, string text, int chatColor, bool isOverlay)
{
	if (isOverlay == true) {
		GamePacket p = packetEnd(appendIntx(appendIntx(appendString(appendIntx(appendString(createPacket(), "OnTalkBubble"),
			((PlayerInfo*)(peer->data))->netID), text), chatColor), 1));

		ENetPacket * packet = enet_packet_create(p.data,
			p.len,
			ENET_PACKET_FLAG_RELIABLE);
		enet_peer_send(peer, 0, packet);
		delete p.data;
	}
	else
	{
		GamePacket p = packetEnd(appendIntx(appendString(appendIntx(appendString(createPacket(), "OnTalkBubble"),
			((PlayerInfo*)(peer->data))->netID), text), chatColor));

		ENetPacket * packet = enet_packet_create(p.data,
			p.len,
			ENET_PACKET_FLAG_RELIABLE);
		enet_peer_send(peer, 0, packet);
		delete p.data;
	}
}

void Player::OnAddNotification(ENetPeer * peer, string text, string audiosound, string interfaceimage)
{
	auto p = packetEnd(appendInt(appendString(appendString(appendString(appendString(createPacket(), "OnAddNotification"),
		interfaceimage),
		text),
		audiosound),
		0));

	ENetPacket * packet = enet_packet_create(p.data,
		p.len,
		ENET_PACKET_FLAG_RELIABLE);
	enet_peer_send(peer, 0, packet);
	delete p.data;
}

