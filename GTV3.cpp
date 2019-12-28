/**********************************************************************************
	First Growtopia Private Server made with ENet.
	Copyright (C) 2018  Growtopia Noobs

	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU Affero General Public License as published
	by the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU Affero General Public License for more details.

	You should have received a copy of the GNU Affero General Public License
	along with this program.  If not, see <http://www.gnu.org/licenses/>.
**********************************************************************************/

#include "stdafx.h"
#include <iostream>
#include <functional>
#include "enet/enet.h"
#include <string>
#ifdef _WIN32
#include <windows.h>
#include <conio.h>
#endif
#ifdef __linux__
#include <stdio.h>
char _getch() {
	return getchar();
}
#endif
#include <vector>
#include <sstream>
#include <chrono>
#include <fstream>
#include "json.hpp"
#ifdef _WIN32
#include "bcrypt.h"
#include "crypt_blowfish/crypt_gensalt.cpp"
#include "crypt_blowfish/crypt_blowfish.h"
#include "crypt_blowfish/crypt_blowfish.cpp"
#include "crypt_blowfish/ow-crypt.cpp"
#include "bcrypt.cpp"
#else
#include "bcrypt.h"
#include "bcrypt.cpp"
#include "crypt_blowfish/crypt_gensalt.h"
#include "crypt_blowfish/crypt_gensalt.cpp"
#include "crypt_blowfish/crypt_blowfish.h"
#include "crypt_blowfish/crypt_blowfish.cpp"
#include "crypt_blowfish/ow-crypt.h"
#include "crypt_blowfish/ow-crypt.cpp"
#include "bcrypt.h"
#endif
#include <thread> // TODO
#include <mutex> // TODO
#include "PlayerDefs.h"
#include "GamePacket.h"
#include "ServerDefs.h"
#include "GTV3Queue.h"
#include "AntiCheat.h"
#include <regex>
#include <mysql.h>
#include <sqlext.h>
#include <sqltypes.h>
#include <sql.h>
#pragma warning(disable : 4996)

using namespace std;
using json = nlohmann::json;

//#define TOTAL_LOG



#define REGISTRATION
#include <signal.h>
#ifdef __linux__
#include <cstdint>
typedef unsigned char BYTE;
typedef unsigned char __int8;
typedef unsigned short __int16;
typedef unsigned int DWORD;
#endif



//Linux equivalent of GetLastError
#ifdef __linux__
string GetLastError() {
	return strerror(errno);
}
//Linux has no byteswap functions.
ulong _byteswap_ulong(ulong x)
{
	// swap adjacent 32-bit blocks
	//x = (x >> 32) | (x << 32);
	// swap adjacent 16-bit blocks
	x = ((x & 0xFFFF0000FFFF0000) >> 16) | ((x & 0x0000FFFF0000FFFF) << 16);
	// swap adjacent 8-bit blocks
	return ((x & 0xFF00FF00FF00FF00) >> 8) | ((x & 0x00FF00FF00FF00FF) << 8);
}
#endif

//configs
int configPort = 17091;


/***bcrypt***/

void showSQLError(unsigned int handleType, const SQLHANDLE& handle) {
	SQLCHAR SQLState[1024];
	SQLCHAR message[1024];
	if (SQL_SUCCESS == SQLGetDiagRec(handleType, handle, 1, SQLState, NULL, message, 1024, NULL)) {
		cout << "SQL driver report/message: " << message << "\nSQL state: " << SQLState << "." << endl;
	}
}

bool verifyPassword(string password, string hash) {
	int ret;

	ret = bcrypt_checkpw(password.c_str(), hash.c_str());
	assert(ret != -1);

	return !ret;
}

string hashPassword(string password) {
	char salt[BCRYPT_HASHSIZE];
	char hash[BCRYPT_HASHSIZE];
	int ret;

	ret = bcrypt_gensalt(12, salt);
	assert(ret == 0);
	ret = bcrypt_hashpw(password.c_str(), salt, hash);
	assert(ret == 0);
	return hash;
}

/***bcrypt**/



void sendTileData(ENetPeer* peer, int x, int y, int visual, uint16_t fgblock, uint16_t bgblock, string tiledata) {
	PlayerMoving pmov;
	pmov.packetType = 5;
	pmov.characterState = 0;
	pmov.x = 0;
	pmov.y = 0;
	pmov.XSpeed = 0;
	pmov.YSpeed = 0;
	pmov.plantingTree = 0;
	pmov.punchX = x;
	pmov.punchY = y;
	pmov.netID = 0;

	string packetstr;
	packetstr.resize(4);
	packetstr[0] = 4;
	packetstr += packPlayerMoving2(&pmov);
	packetstr[16] = 8;
	packetstr.resize(packetstr.size() + 4);
	STRINT(packetstr, 52 + 4) = tiledata.size() + 4;
	STR16(packetstr, 56 + 4) = fgblock;
	STR16(packetstr, 58 + 4) = bgblock;
	packetstr += tiledata;

	ENetPacket* packet = enet_packet_create(&packetstr[0],
		packetstr.length(),
		ENET_PACKET_FLAG_RELIABLE);

	enet_peer_send(peer, 0, packet);
}




void sendData(ENetPeer* peer, int num, char* data, int len)
{
	/* Create a reliable packet of size 7 containing "packet\0" */
	ENetPacket * packet = enet_packet_create(0,
		len + 5,
		ENET_PACKET_FLAG_RELIABLE);
	/* Extend the packet so and append the string "foo", so it now */
	/* contains "packetfoo\0"                                      */
	/* Send the packet to the peer over channel id 0. */
	/* One could also broadcast the packet by         */
	/* enet_host_broadcast (host, 0, packet);         */
	memcpy(packet->data, &num, 4);
	if (data != NULL)
	{
		memcpy(packet->data + 4, data, len);
	}
	char zero = 0;
	memcpy(packet->data + 4 + len, &zero, 1);
	enet_peer_send(peer, 0, packet);
	enet_host_flush(server);
}

int getPacketId(char* data)
{
	return *data;
}

char* getPacketData(char* data)
{
	return data + 4;
}

string filterName(string  name) {
	string filteredname = "";
	for (int i = 0; i < name.length(); i++) {
		string ch = name.substr(i, 1); // always take 1 character, and move next. EXAMPLE: we got password 12345, it will take first 1 and check, then 2 and check, and 3 and check, 4 and check, 5 and ccheck. it will scan ALL characters if bad symbols etc. because i is always getting a higher number cuz we said i++
		if (ch != "a" && ch != "A" && ch != "b" && ch != "B" && ch != "c" && ch != "C" && ch != "d" && ch != "D" && ch != "e" && ch != "E"
			&& ch != "f" && ch != "F" && ch != "g" && ch != "G" && ch != "h" && ch != "H" && ch != "i" && ch != "I" && ch != "j" && ch != "J"
			&& ch != "k" && ch != "K" && ch != "l" && ch != "L" && ch != "m" && ch != "M" && ch != "n" && ch != "N" && ch != "o" && ch != "O" &&
			ch != "p" && ch != "P" && ch != "q" && ch != "Q" && ch != "r" && ch != "R" && ch != "s" && ch != "S" && ch != "t" && ch != "T" && ch != "u" && ch != "U"
			&& ch != "v" && ch != "V" && ch != "w" && ch != "W" && ch != "x" && ch != "X" && ch != "y" && ch != "Y" && ch != "z" && ch != "Z" && ch != "0" && ch != "1" && ch != "2"
			&& ch != "3" && ch != "4" && ch != "5" && ch != "6" && ch != "7" && ch != "8" && ch != "9") {
		}
		else
		{
			filteredname = filteredname + ch;
		}
	}
	return filteredname;
}

string text_encode(char* text)
{
	string ret = "";
	while (text[0] != 0)
	{
		switch (text[0])
		{
		case '\n':
			ret += "\\n";
			break;
		case '\t':
			ret += "\\t";
			break;
		case '\b':
			ret += "\\b";
			break;
		case '\\':
			ret += "\\\\";
			break;
		case '\r':
			ret += "\\r";
			break;
		default:
			ret += text[0];
			break;
		}
		text++;
	}
	return ret;
}





char* GetTextPointerFromPacket(ENetPacket* packet)
{
	char zero = 0;
	memcpy(packet->data + packet->dataLength - 1, &zero, 1);
	return (char*)(packet->data + 4);
}

BYTE* GetStructPointerFromTankPacket(ENetPacket* packet)
{
	logs << "Getting Struct Pointer of packet..." << endl;
	logs.flush();
	unsigned int packetLenght = packet->dataLength;
	BYTE* result = NULL;
	if (packetLenght >= 0x3C)
	{
		BYTE* packetData = packet->data;
		result = packetData + 4;
		if (*(BYTE*)(packetData + 16) & 8)
		{
			if (packetLenght < *(int*)(packetData + 56) + 60)
			{
				cout << "Packet too small for extended packet to be valid" << endl;
				cout << "Sizeof float is 4.  TankUpdatePacket size: 56" << endl;
				result = 0;
			}
		}
		else
		{
			int zero = 0;
			memcpy(packetData + 56, &zero, 4);
		}
	}
	return result;
}

int GetMessageTypeFromPacket(ENetPacket* packet)
{
	int result = 0;

	if (packet->dataLength > 3u && *packet->data != NULL)
	{
		if (result > -1 && result < 99) {
			result = (int)*(packet->data);
		}
	}
	else
	{
		cout << "Bad packet length, ignoring message" << endl;
		result = 0;
	}
	return result;
}


vector<string> explode(const string &delimiter, const string &str)
{
	vector<string> arr;

	int strleng = str.length();
	int delleng = delimiter.length();
	if (delleng == 0)
		return arr;//no change

	int i = 0;
	int k = 0;
	while (i < strleng)
	{
		int j = 0;
		while (i + j < strleng && j < delleng && str[i + j] == delimiter[j])
			j++;
		if (j == delleng)//found delimiter
		{
			arr.push_back(str.substr(k, i - k));
			i += delleng;
			k = i;
		}
		else
		{
			i++;
		}
	}
	arr.push_back(str.substr(k, i - k));
	return arr;
}

WorldInfo generateWorld(string name, int width, int height)
{

	WorldInfo world;
	world.name = name;
	world.width = width;
	world.height = height;
	world.items = new WorldItem[world.width*world.height];
	for (int i = 0; i < world.width*world.height; i++)
	{
		if (i >= 3800 && i < 5400 && !(rand() % 50)) { world.items[i].foreground = 10; }
		else if (i >= 3700 && i < 5400) {
			if (i > 5000) {
				if (i % 7 == 0) { world.items[i].foreground = 4; }
				else { world.items[i].foreground = 2; }
			}
			else { world.items[i].foreground = 2; }
		}
		else if (i >= 5400) { world.items[i].foreground = 8; }
		if (i >= 3700)
			world.items[i].background = 14;
		if (i == 3650)
			world.items[i].foreground = 6;
		else if (i >= 3600 && i < 3700)
			world.items[i].foreground = 0; //fixed the grass in the world!
		if (i == 3750)
			world.items[i].foreground = 8;
	}
	return world;
}

class PlayerDB {
public:
	static string getProperName(string name);
	static string fixColors(string text);
	static int playerLogin(ENetPeer* peer, string username, string password);
	static int playerRegister(ENetPeer* peer, string username, string password, string passwordverify, string email, string discord);
	static int guildRegister(ENetPeer* peer, string guildName, string guildStatement, string guildFlagfg, string guildFlagbg);
};


struct Admin {
	string username;
	string password;
	int level = 0;
	long long int lastSB = 0;
};

vector<Admin> admins;

void addAdmin(string username, string password, int level)
{
	Admin admin;
	admin.username = username;
	admin.password = password;
	admin.level = level;
	admins.push_back(admin);
}

string PlayerDB::getProperName(string name) {
	string newS;
	for (char c : name) newS += (c >= 'A' && c <= 'Z') ? c - ('A' - 'a') : c;
	string ret;
	for (int i = 0; i < newS.length(); i++)
	{
		if (newS[i] == '`') i++; else ret += newS[i];
	}
	string ret2;
	for (char c : ret) if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) ret2 += c;

	string username = ret2;
	if (username == "prn" || username == "con" || username == "aux" || username == "nul" || username == "com1" || username == "com2" || username == "com3" || username == "com4" || username == "com5" || username == "com6" || username == "com7" || username == "com8" || username == "com9" || username == "lpt1" || username == "lpt2" || username == "lpt3" || username == "lpt4" || username == "lpt5" || username == "lpt6" || username == "lpt7" || username == "lpt8" || username == "lpt9") {
		return "";
	}

	return ret2;
}

string PlayerDB::fixColors(string text) {
	string ret = "";
	int colorLevel = 0;
	for (int i = 0; i < text.length(); i++)
	{
		if (text[i] == '`')
		{
			ret += text[i];
			if (i + 1 < text.length())
				ret += text[i + 1];


			if (i + 1 < text.length() && text[i + 1] == '`')
			{
				colorLevel--;
			}
			else {
				colorLevel++;
			}
			i++;
		}
		else {
			ret += text[i];
		}
	}
	for (int i = 0; i < colorLevel; i++) {
		ret += "``";
	}
	for (int i = 0; i > colorLevel; i--) {
		ret += "`w";
	}
	return ret;
}

string filterPass(string password) {

	string filteredpass = "";
	for (int i = 0; i < password.length(); i++) {
		string ch = password.substr(i, 1); // always take 1 character, and move next. EXAMPLE: we got password 12345, it will take first 1 and check, then 2 and check, and 3 and check, 4 and check, 5 and ccheck. it will scan ALL characters if bad symbols etc. because i is always getting a higher number cuz we said i++
		if (ch != "a" && ch != "A" && ch != "b" && ch != "B" && ch != "c" && ch != "C" && ch != "d" && ch != "D" && ch != "e" && ch != "E"
			&& ch != "f" && ch != "F" && ch != "g" && ch != "G" && ch != "h" && ch != "H" && ch != "i" && ch != "I" && ch != "j" && ch != "J"
			&& ch != "k" && ch != "K" && ch != "l" && ch != "L" && ch != "m" && ch != "M" && ch != "n" && ch != "N" && ch != "o" && ch != "O" &&
			ch != "p" && ch != "P" && ch != "q" && ch != "Q" && ch != "r" && ch != "R" && ch != "s" && ch != "S" && ch != "t" && ch != "T" && ch != "u" && ch != "U"
			&& ch != "v" && ch != "V" && ch != "w" && ch != "W" && ch != "x" && ch != "X" && ch != "y" && ch != "Y" && ch != "z" && ch != "Z" && ch != "0" && ch != "1" && ch != "2"
			&& ch != "3" && ch != "4" && ch != "5" && ch != "6" && ch != "7" && ch != "8" && ch != "9" && ch != "!" && ch != ".") {

		}
		else
		{
			filteredpass = filteredpass + ch;
		}
	}
	return filteredpass;
}

int PlayerDB::playerLogin(ENetPeer* peer, string username, string password) {
	
	if (username.length() > 16) return -1;
	if (password.length() > 20) return -1;
	string uname = filterName(username);
	string passw = filterPass(password);
	if (uname == "" || passw == "") return -1;
	int qstate = 0;
	MYSQL_ROW row;	
	string receiveduser = "";
	string receivedName = "";
	string xd = "";
	int gem = 0;
	int skColor = 0;
	string receiveduserId = "";
	
	conn = mysql_init(0);
	conn = mysql_real_connect(conn, ip, user, pass, database, 0, NULL, 0);

	if (conn == NULL) return -1;
			
	stringstream ss; // creating string stream to load in query
	ss << "SELECT * FROM players WHERE username = '" + uname + "' AND password = '" + passw + "'";
	if (!ss.fail()) {
		string query = ss.str();
		const char* q = query.c_str();
		qstate = mysql_query(conn, q);
	}
	if (qstate == 0) {
		res = mysql_store_result(conn);
		while (row = mysql_fetch_row(res)) {
			receiveduser = row[0];
			xd = row[2];
			receivedName = row[4];
			receiveduserId = row[5];
			((PlayerInfo*)(peer->data))->cloth_hair = atoi(row[6]);
			((PlayerInfo*)(peer->data))->cloth_shirt = atoi(row[7]);
			((PlayerInfo*)(peer->data))->cloth_pants = atoi(row[8]);
			((PlayerInfo*)(peer->data))->cloth_feet = atoi(row[9]);
			((PlayerInfo*)(peer->data))->cloth_face = atoi(row[10]);
			((PlayerInfo*)(peer->data))->cloth_hand = atoi(row[11]);
			((PlayerInfo*)(peer->data))->cloth_back = atoi(row[12]);
			((PlayerInfo*)(peer->data))->cloth_mask = atoi(row[13]);
			((PlayerInfo*)(peer->data))->cloth_necklace = atoi(row[14]);
			((PlayerInfo*)(peer->data))->cloth_ances = atoi(row[15]);
			skColor = atoi(row[16]);
			((PlayerInfo*)(peer->data))->canWalkInBlocks = atoi(row[17]);
			((PlayerInfo*)(peer->data))->isinv = atoi(row[18]);



		}
		if (skColor != 0) ((PlayerInfo*)(peer->data))->skinColor = skColor;
		gem = atoi(xd.c_str());
		if (receiveduser == "") {
			//delete res;
			return -1;
		}
		((PlayerInfo*)(peer->data))->userID = atoi(receiveduserId.c_str());
		((PlayerInfo*)(peer->data))->displayName = receivedName;
		((PlayerInfo*)(peer->data))->displayNamebackup = receivedName;
		((PlayerInfo*)(peer->data))->gems = gem;
	}
	//delete res;
	mysql_close(conn);
	bool on = false;
	ENetPeer * currentPeer;
	for (currentPeer = server->peers;
		currentPeer < &server->peers[server->peerCount];
		++currentPeer)
	{
		if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
			continue;
		if (((PlayerInfo*)(peer->data))->userID == ((PlayerInfo*)(currentPeer->data))->userID) {
			if (peer != currentPeer) {
				on = true;
				//enet_peer_disconnect_now(currentPeer, 0);
			}
		}
	}
	if (on) Player::OnConsoleMessage(peer, "`4ALREADY ON??? `wIf you were online before this is nothing to worry about.``");
	return 1;
}



int PlayerDB::playerRegister(ENetPeer* peer, string username, string password, string passwordverify, string email, string discord) {
	string name = username;
	string dName = username;
	username = PlayerDB::getProperName(username);
	if (discord.find("#") == std::string::npos && discord.length() != 0) return -5;
	if (email.find("@") == std::string::npos && email.length() != 0) return -4;
	if (password.length() < 3) return -2;
	if (passwordverify != password) return -3;
	if (username.length() < 3) return -2;
	if (username.length() > 16) return -2;
	if (password.length() > 20) return -2;
	MYSQL_ROW row;
	conn = mysql_init(0);
	conn = mysql_real_connect(conn, ip, user, pass, database, 0, NULL, 0);
	if (conn == NULL) {
		return -1;
	}

	if (conn != NULL) {
		stringstream sse;
		string name;
		int qstate2 = 0;
		sse << "SELECT * FROM players WHERE username = '" + PlayerDB::getProperName(username) + "'";
		if (!sse.fail()) {
			string query = sse.str();
			const char* q = query.c_str();
			qstate2 = mysql_query(conn, q);
		}
		if (qstate2 == 0) {
			res = mysql_store_result(conn);
			while (row = mysql_fetch_row(res)) {
				name = row[0];
			}
			if (name.length() > 0) return -1;
		}
		else {
			return -1;
		}
		totaluserids++;
		if (totaluserids == 1) totaluserids++;
		int qstate = 0;


		stringstream ss;
		ss << "INSERT INTO players(username, password, gems, ban, displayName, userId, hair, shirt, pants, feet, face, hand, back, mask, neck, ances, skincolor, Ghost, invis) VALUES('" << PlayerDB::getProperName(username) << "', '" << filterPass(password) << "', '0', '0', '" << filterName(dName) << "', '" << totaluserids << "', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0')"; // in display name too! fix sql injection because in PASSWORD people can put character like ' and it will crash/inject something that we dont want (dangerous stuff) TODO
		string query = ss.str(); // loading query into string
		const char* q = query.c_str(); // converting string to const char
		qstate = mysql_query(conn, q);
		if (qstate == 0) { // if qstate == 0 (EVERYTHING IS OK!) then pop out a 1, 1 will lead to the dialog that will say ("GrowID Created")			
		}
		else {
			return -1;
		}

	}
	else {
		return -1;
	}
	mysql_close(conn);

	ofstream myfile;
	myfile.open("totaluids.txt");
	myfile << to_string(totaluserids);
	myfile.close();
	((PlayerInfo*)(peer->data))->userID = totaluserids;
	return 1;
}

struct AWorld {
	WorldInfo* ptr;
	WorldInfo info;
	int id;
};

class WorldDB {
public:
	WorldInfo get(string name);
	AWorld get2(string name);
	int getworldStatus(string name);
	void flush(WorldInfo info);
	void flush2(AWorld info);
	void save(AWorld info);
	void saveAll();
	void saveRedundant();
	vector<WorldInfo> getRandomWorlds();
	WorldDB();
private:
	vector<WorldInfo> worlds;
};

WorldDB::WorldDB() {
	// Constructor
}


void sendConsoleMsg(ENetPeer* peer, string message) {
	Player::OnConsoleMessage(peer, message);
}

string getStrUpper(string txt) {
	string ret;
	for (char c : txt) ret += toupper(c);
	return ret;
}

AWorld WorldDB::get2(string name) {
	if (worlds.size() > 200) {
#ifdef TOTAL_LOG
		cout << "Saving redundant worlds!" << endl;
#endif
		saveRedundant();
#ifdef TOTAL_LOG
		cout << "Redundant worlds are saved!" << endl;
#endif
	}


	AWorld ret;
	name = getStrUpper(name);
	if (name.length() < 1) throw 1; // too short name
	for (char c : name) {
		if ((c<'A' || c>'Z') && (c<'0' || c>'9'))
			throw 2; // wrong name
	}
	if (name == "EXIT") {
		throw 3;
	}
	//if (name == "CON" || name == "PRN" || name == "AUX" || name == "NUL" || name == "COM1" || name == "COM2" || name == "COM3" || name == "COM4" || name == "COM5" || name == "COM6" || name == "COM7" || name == "COM8" || name == "COM9" || name == "LPT1" || name == "LPT2" || name == "LPT3" || name == "LPT4" || name == "LPT5" || name == "LPT6" || name == "LPT7" || name == "LPT8" || name == "LPT9") throw 3;
	for (int i = 0; i < worlds.size(); i++) {
		if (worlds.at(i).name == name)
		{
			ret.id = i;
			ret.info = worlds.at(i);
			ret.ptr = &worlds.at(i);
			return ret;
		}

	}
	std::ifstream ifs("worlds/_" + name + ".json");
	if (ifs.is_open()) {

		json j;
		ifs >> j;
		WorldInfo info;
		info.name = j["name"].get<string>();
		info.width = j["width"];
		info.height = j["height"];
		info.owner = j["owner"].get<string>();
		info.ownerId = j["ownerId"];
		info.isPublic = j["isPublic"];
		json tiles = j["tiles"];
		int square = info.width*info.height;
		info.items = new WorldItem[square];
		for (int i = 0; i < square; i++) {
			info.items[i].foreground = tiles[i]["fg"];
			info.items[i].background = tiles[i]["bg"];
			info.items[i].sign = tiles[i]["s"];
			info.items[i].displayBlock = tiles[i]["d"];
			info.items[i].gravity = tiles[i]["gr"];
		}
		worlds.push_back(info);
		ret.id = worlds.size() - 1;
		ret.info = info;
		ret.ptr = &worlds.at(worlds.size() - 1);
		return ret;
	}
	else {
		WorldInfo info = generateWorld(name, 100, 60);

		worlds.push_back(info);
		ret.id = worlds.size() - 1;
		ret.info = info;
		ret.ptr = &worlds.at(worlds.size() - 1);
		return ret;
	}
	throw 1;
}

WorldInfo WorldDB::get(string name) {

	return this->get2(name).info;
}

int WorldDB::getworldStatus(string name) {
	name = getStrUpper(name);
	//if (name == "CON" || name == "PRN" || name == "AUX" || name == "NUL" || name == "COM1" || name == "COM2" || name == "COM3" || name == "COM4" || name == "COM5" || name == "COM6" || name == "COM7" || name == "COM8" || name == "COM9" || name == "LPT1" || name == "LPT2" || name == "LPT3" || name == "LPT4" || name == "LPT5" || name == "LPT6" || name == "LPT7" || name == "LPT8" || name == "LPT9") return -1;

	//if (name.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") != string::npos) return -1;
	if (name.length() > 24) return -1;
	/*for (int i = 0; i < worlds.size(); i++) {
		if (worlds.at(i).name == name)
		{
			return 0;
		}
	}*/
	return 0;
}

void WorldDB::flush(WorldInfo info)
{
	std::ofstream o("worlds/_" + info.name + ".json");
	if (!o.is_open()) {
		cout << GetLastError() << endl;
	}
	json j;
	j["name"] = info.name;
	j["width"] = info.width;
	j["height"] = info.height;
	j["owner"] = info.owner;
	j["isPublic"] = info.isPublic;
	j["ownerId"] = info.ownerId;
	json tiles = json::array();
	int square = info.width*info.height;

	for (int i = 0; i < square; i++)
	{
		json tile;
		tile["fg"] = info.items[i].foreground;
		tile["bg"] = info.items[i].background;
		tile["s"] = info.items[i].sign;
		tile["d"] = info.items[i].displayBlock;
		tile["gr"] = info.items[i].gravity;
		tiles.push_back(tile);
	}
	j["tiles"] = tiles;
	o << j << std::endl;
}

void WorldDB::flush2(AWorld info)
{
	this->flush(info.info);
}

void WorldDB::save(AWorld info)
{
	flush2(info);
	delete info.info.items;
	worlds.erase(worlds.begin() + info.id);
}

void WorldDB::saveAll()
{
	for (int i = 0; i < worlds.size(); i++) {
		flush(worlds.at(i));

	}
	worlds.clear();
}

vector<WorldInfo> WorldDB::getRandomWorlds() {
	vector<WorldInfo> ret;
	for (int i = 0; i < ((worlds.size() < 10) ? worlds.size() : 10); i++)
	{ // load first four worlds, it is excepted that they are special
		ret.push_back(worlds.at(i));
	}
	// and lets get up to 6 random
	if (worlds.size() > 4) {
		for (int j = 0; j < 6; j++)
		{
			bool isPossible = true;
			WorldInfo world = worlds.at(rand() % (worlds.size() - 4));
			for (int i = 0; i < ret.size(); i++)
			{
				if (world.name == ret.at(i).name || world.name == "EXIT")
				{
					isPossible = false;
				}
			}
			if (isPossible)
				ret.push_back(world);
		}
	}
	return ret;
}

void WorldDB::saveRedundant()
{
	for (int i = 4; i < worlds.size(); i++) {
		bool canBeFree = true;
		ENetPeer * currentPeer;

		for (currentPeer = server->peers;
			currentPeer < &server->peers[server->peerCount];
			++currentPeer)
		{
			if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
				continue;
			if (((PlayerInfo*)(currentPeer->data))->currentWorld == worlds.at(i).name)
				canBeFree = false;
		}
		if (canBeFree)
		{
			flush(worlds.at(i));
			delete worlds.at(i).items;
			worlds.erase(worlds.begin() + i);
			i--;
		}
	}
}

//WorldInfo world;
//vector<WorldInfo> worlds;
WorldDB worldDB;

void saveAllWorlds() // atexit hack plz fix
{
	serverIsFrozen = true;
	cout << "Saving worlds..." << endl;
	worldDB.saveAll();
	cout << "Worlds saved!" << endl;
	Sleep(1000);
	serverIsFrozen = false;
	Sleep(200);
	GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`2Saved all worlds successfully`w!``"));
	ENetPacket * packet = enet_packet_create(p.data,
		p.len,
		ENET_PACKET_FLAG_RELIABLE);
	enet_host_broadcast(server, 0, packet);
	delete p.data;
}

WorldInfo* getPlyersWorld(ENetPeer* peer)
{
	try {
		return worldDB.get2(((PlayerInfo*)(peer->data))->currentWorld).ptr;
	}
	catch (int e) {
		return NULL;
	}
}




enum ClothTypes {
	HAIR,
	SHIRT,
	PANTS,
	FEET,
	FACE,
	HAND,
	BACK,
	MASK,
	NECKLACE,
	ANCES,
	NONE
};

enum BlockTypes {
	FOREGROUND,
	BACKGROUND,
	CONSUMABLE,
	SEED,
	CHECKPOINT,
	WRENCH,
	LOCK,
	GATEWAY,
	PLATFORM,
	SWITCH_BLOCK,
	TRAMPOLINE,
	TOGGLE_FOREGROUND,
	ANIM_FOREGROUND,
	BOUNCY,
	BULLETIN_BOARD,
	CHEST,
	COMPONENT,
	DEADLY,
	FACTION,
	GEMS,
	MAGIC_EGG,
	PORTAL,
	RANDOM_BLOCK,
	SFX_FOREGROUND,
	TREASURE,
	PAIN_BLOCK,
	BEDROCK,
	MAIN_DOOR,
	SIGN,
	DOOR,
	CLOTHING,
	MAILBOX,
	FIST,
	UNKNOWN
};

struct ItemDefinition {
	int id;
	string name;
	int rarity;
	int breakHits;
	int growTime;
	ClothTypes clothType;
	BlockTypes blockType;
	string description = "This item has no description.";
	int properties;
};

vector<ItemDefinition> itemDefs;




ItemDefinition getItemDef(int id)
{
	if (id > coredatasize - 2) return itemDefs.at(0);
	if (id < itemDefs.size() && id > -1)
		return itemDefs.at(id);
	/*for (int i = 0; i < itemDefs.size(); i++)
	{
		if (id == itemDefs.at(i).id)
		{
			return itemDefs.at(i);
		}
	}*/
	throw 0;
	return itemDefs.at(0);
}

void craftItemDescriptions() {
	int current = -1;
	std::ifstream infile("Descriptions.txt");
	for (std::string line; getline(infile, line);)
	{
		if (line.length() > 3 && line[0] != '/' && line[1] != '/')
		{
			vector<string> ex = explode("|", line);
			ItemDefinition def;
			if (atoi(ex[0].c_str()) + 1 < itemDefs.size())
			{
				itemDefs.at(atoi(ex[0].c_str())).description = ex[1];
				if (!(atoi(ex[0].c_str()) % 2))
					itemDefs.at(atoi(ex[0].c_str()) + 1).description = "This is a tree.";
			}
		}
	}
}



void sendDrop(ENetPeer* peer, int netID, int x, int y, int item, int count, BYTE specialEffect, WorldInfo* world)
{

	if (item >= coredatasize - 2) return;
	if (item < 0) return;
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
			data.plantingTree = item;
			float val = count; // item count
			BYTE val2 = specialEffect;

			BYTE* raw = packPlayerMoving(&data);
			memcpy(raw + 16, &val, 4);
			memcpy(raw + 1, &val2, 1);

			SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
		}
	}

	((PlayerInfo*)(peer->data))->droppeditemcount++;
}

void dropItem(ENetPeer* peer, int netID, int x, int y, int item, int count, BYTE specialEffect, WorldInfo* world)
{

	if (!world) return;
	if (item > itemsize) return;
	if (item < 0) return;


	//world->droppedCount++;
	removeInventoryItem(peer, item, count);
	//int dcount = world->droppedCount;
	// TODO


	sendDrop(peer, netID, x, y, item, count, specialEffect, world);
}

void buildItemsDatabase()
{
	int current = -1;
	std::ifstream infile("CoreData.txt");
	for (std::string line; getline(infile, line);)
	{
		if (line.length() > 8 && line[0] != '/' && line[1] != '/')
		{
			coredatasize++;
			vector<string> ex = explode("|", line);
			ItemDefinition def;
			def.id = atoi(ex[0].c_str());
			def.name = ex[1];
			def.rarity = atoi(ex[2].c_str());
			vector<string> properties = explode(",", ex[3]);
			def.properties = Property_Zero;
			for (auto &prop : properties)
			{
				if (prop == "NoSeed")
					def.properties |= Property_NoSeed;
				if (prop == "Dropless")
					def.properties |= Property_Dropless;
				if (prop == "Beta")
					def.properties |= Property_Beta;
				if (prop == "Mod")
					def.properties |= Property_Mod;
				if (prop == "Untradable")
					def.properties |= Property_Untradable;
				if (prop == "Wrenchable")
					def.properties |= Property_Wrenchable;
				if (prop == "MultiFacing")
					def.properties |= Property_MultiFacing;
				if (prop == "Permanent")
					def.properties |= Property_Permanent;
				if (prop == "AutoPickup")
					def.properties |= Property_AutoPickup;
				if (prop == "WorldLock")
					def.properties |= Property_WorldLock;
				if (prop == "NoSelf")
					def.properties |= Property_NoSelf;
				if (prop == "RandomGrow")
					def.properties |= Property_RandomGrow;
				if (prop == "Public")
					def.properties |= Property_Public;
			}
			string bt = ex[4];
			if (bt == "Foreground_Block") {
				def.blockType = BlockTypes::FOREGROUND;
			}
			else if (bt == "Seed") {
				def.blockType = BlockTypes::SEED;
			}
			else if (bt == "Consummable") {
				def.blockType = BlockTypes::CONSUMABLE;
			}
			else if (bt == "Pain_Block") {
				def.blockType = BlockTypes::PAIN_BLOCK;
			}
			else if (bt == "Main_Door") {
				def.blockType = BlockTypes::MAIN_DOOR;
			}
			else if (bt == "Bedrock") {
				def.blockType = BlockTypes::BEDROCK;
			}
			else if (bt == "Door") {
				def.blockType = BlockTypes::DOOR;
			}
			else if (bt == "Fist") {
				def.blockType = BlockTypes::FIST;
			}
			else if (bt == "Sign") {
				def.blockType = BlockTypes::SIGN;
			}
			else if (bt == "Background_Block") {
				def.blockType = BlockTypes::BACKGROUND;
			}
			else if (bt == "Sheet_Music") {
				def.blockType = BlockTypes::BACKGROUND;
			}
			else if (bt == "Wrench") {
				def.blockType = BlockTypes::WRENCH;
			}
			else if (bt == "Checkpoint") {
				def.blockType = BlockTypes::CHECKPOINT;
			}
			else if (bt == "Lock") {
				def.blockType = BlockTypes::LOCK;
			}
			else if (bt == "Gateway") {
				def.blockType = BlockTypes::GATEWAY;
			}
			else if (bt == "Clothing") {
				def.blockType = BlockTypes::CLOTHING;
			}
			else if (bt == "Platform") {
				def.blockType = BlockTypes::PLATFORM;
			}
			else if (bt == "SFX_Foreground") {
				def.blockType = BlockTypes::SFX_FOREGROUND;
			}
			else if (bt == "Gems") {
				def.blockType = BlockTypes::GEMS;
			}
			else if (bt == "Toggleable_Foreground") {
				def.blockType = BlockTypes::TOGGLE_FOREGROUND;
			}
			else if (bt == "Treasure") {
				def.blockType = BlockTypes::TREASURE;
			}
			else if (bt == "Deadly_Block") {
				def.blockType = BlockTypes::DEADLY;
			}
			else if (bt == "Trampoline_Block") {
				def.blockType = BlockTypes::TRAMPOLINE;
			}
			else if (bt == "Animated_Foreground_Block") {
				def.blockType = BlockTypes::ANIM_FOREGROUND;
			}
			else if (bt == "Portal") {
				def.blockType = BlockTypes::PORTAL;
			}
			else if (bt == "Random_Block") {
				def.blockType = BlockTypes::RANDOM_BLOCK;
			}
			else if (bt == "Bouncy") {
				def.blockType = BlockTypes::BOUNCY;
			}
			else if (bt == "Chest") {
				def.blockType = BlockTypes::CHEST;
			}
			else if (bt == "Switch_Block") {
				def.blockType = BlockTypes::SWITCH_BLOCK;
			}
			else if (bt == "Magic_Egg") {
				def.blockType = BlockTypes::MAGIC_EGG;
			}
			else if (bt == "Mailbox") {
				def.blockType = BlockTypes::MAILBOX;
			}
			else if (bt == "Bulletin_Board") {
				def.blockType = BlockTypes::BULLETIN_BOARD;
			}
			else if (bt == "Faction") {
				def.blockType = BlockTypes::FACTION;
			}
			else if (bt == "Component") {
				def.blockType = BlockTypes::COMPONENT;
			}
			else {
				//cout << "Unknown property for ID: " << def.id << " which wants property " << bt << endl;
				def.blockType = BlockTypes::UNKNOWN;
			}
			def.breakHits = atoi(ex[7].c_str());
			def.growTime = atoi(ex[8].c_str());
			string cl = ex[9];
			if (def.blockType == BlockTypes::CLOTHING)
			{
				if (cl == "None") {
					def.clothType = ClothTypes::NONE;
				}
				else if (cl == "Hat") {
					def.clothType = ClothTypes::HAIR;
				}
				else if (cl == "Shirt") {
					def.clothType = ClothTypes::SHIRT;
				}
				else if (cl == "Pants") {
					def.clothType = ClothTypes::PANTS;
				}
				else if (cl == "Feet") {
					def.clothType = ClothTypes::FEET;
				}
				else if (cl == "Face") {
					def.clothType = ClothTypes::FACE;
				}
				else if (cl == "Hand") {
					def.clothType = ClothTypes::HAND;
				}
				else if (cl == "Back") {
					def.clothType = ClothTypes::BACK;
				}
				else if (cl == "Hair") {
					def.clothType = ClothTypes::MASK;
				}
				else if (cl == "Chest") {
					def.clothType = ClothTypes::NECKLACE;
				}
				else {
					def.clothType = ClothTypes::NONE;
				}
			}
			else
			{
				def.clothType = ClothTypes::NONE;
			}

			if (++current != def.id)
			{
				cout << "Critical error! Unordered database at item " << std::to_string(current) << "/" << std::to_string(def.id) << "!" << endl;
			}

			itemDefs.push_back(def);
		}
	}
	craftItemDescriptions();

}



int getAdminLevel(string username, string password) {
	for (int i = 0; i < admins.size(); i++) {
		Admin admin = admins[i];
		if (admin.username == username && admin.password == password) {
			return admin.level;
		}
	}
	return 0;
}

bool canSB(string username, string password) {
	for (int i = 0; i < admins.size(); i++) {
		Admin admin = admins[i];
		if (admin.username == username && admin.password == password && admin.level > 1) {
			using namespace std::chrono;
			if (admin.lastSB + 900000 < (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count() || admin.level == 999)
			{
				admins[i].lastSB = (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count();
				return true;
			}
			else {
				return false;
			}
		}
	}
	return false;
}

bool canClear(string username, string password) {
	for (int i = 0; i < admins.size(); i++) {
		Admin admin = admins[i];
		if (admin.username == username && admin.password == password) {
			return admin.level > 1;
		}
	}
	return false;
}

bool isAdminPeer(ENetPeer* peer) {
	for (int i = 0; i < admins.size(); i++) {
		Admin admin = admins[i];
		if (admin.username == ((PlayerInfo*)(peer->data))->rawName && admin.password == ((PlayerInfo*)(peer->data))->rawName && admin.level > 2) {
			return true;
		}
	}
	return false;
}

bool isSuperAdmin(string username, string password) {
	for (int i = 0; i < admins.size(); i++) {
		Admin admin = admins[i];
		if (admin.username == username && admin.password == password && admin.level > 3) {
			return true;
		}
	}
	return false;
}

void SendPacket(int a1, string a2, ENetPeer* enetPeer)
{
	if (enetPeer)
	{
		ENetPacket* v3 = enet_packet_create(0, a2.length() + 5, 1);
		memcpy(v3->data, &a1, 4);
		//*(v3->data) = (DWORD)a1;
		memcpy((v3->data) + 4, a2.c_str(), a2.length());

		//cout << std::hex << (int)(char)v3->data[3] << endl;
		enet_peer_send(enetPeer, 0, v3);
	}
}

void onPeerConnect(ENetPeer* peer)
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
				string netIdS = std::to_string(((PlayerInfo*)(currentPeer->data))->netID);
				GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnSpawn"), "spawn|avatar\nnetID|" + netIdS + "\nuserID|" + netIdS + "\ncolrect|0|0|20|30\nposXY|" + std::to_string(((PlayerInfo*)(currentPeer->data))->x) + "|" + std::to_string(((PlayerInfo*)(currentPeer->data))->y) + "\nname|``" + ((PlayerInfo*)(currentPeer->data))->displayName + "``\ncountry|" + ((PlayerInfo*)(currentPeer->data))->country + "\ninvis|" + to_string(((PlayerInfo*)(currentPeer->data))->isinv) + "\nmstate|" + to_string(((PlayerInfo*)(currentPeer->data))->mstate) + "\nsmstate|" + to_string(((PlayerInfo*)(currentPeer->data))->smstate) + "\n"));
				ENetPacket * packet = enet_packet_create(p.data,
					p.len,
					ENET_PACKET_FLAG_RELIABLE);

				enet_peer_send(peer, 0, packet);
				delete p.data;
				//Player::OnTalkBubble(peer, atoi(netIdS.c_str()), ((PlayerInfo*)(currentPeer->data))->displayName, 0, false);
				string netIdS2 = std::to_string(((PlayerInfo*)(peer->data))->netID);

				GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnSpawn"), "spawn|avatar\nnetID|" + netIdS2 + "\nuserID|" + netIdS2 + "\ncolrect|0|0|20|30\nposXY|" + std::to_string(((PlayerInfo*)(peer->data))->x) + "|" + std::to_string(((PlayerInfo*)(peer->data))->y) + "\nname|``" + ((PlayerInfo*)(peer->data))->displayName + "``\ncountry|" + ((PlayerInfo*)(peer->data))->country + "\ninvis|" + to_string(((PlayerInfo*)(peer->data))->isinv) + "\nmstate|" + to_string(((PlayerInfo*)(peer->data))->mstate) + "\nsmstate|" + to_string(((PlayerInfo*)(peer->data))->smstate) + "\n"));
				ENetPacket * packet2 = enet_packet_create(p2.data,
					p2.len,
					ENET_PACKET_FLAG_RELIABLE);
				enet_peer_send(currentPeer, 0, packet2);
				delete p2.data;
				//`5<`w" + player->displayName + "`` left, `w" + std::to_string(getPlayersCountInWorld(player->currentWorld)) + "`` others here>``
				//Player::OnTalkBubble(currentPeer, atoi(netIdS2.c_str()), "`5<`w" + ((PlayerInfo*)(peer->data))->displayName + "`` entered, `w" + std::to_string(getPlayersCountInWorld(((PlayerInfo*)(peer->data))->currentWorld)) + "`` others here>``", 0, false);
				//enet_host_flush(server);
			}
		}
	}

}







void testCount(ENetPeer * peer) {
	using namespace std::chrono;
	if (((PlayerInfo*)(peer->data))->packetsec + 1000 > (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count()) {
		if (((PlayerInfo*)(peer->data))->packetinsec >= 50) {
			enet_peer_reset(peer);
		}
		else {
			((PlayerInfo*)(peer->data))->packetinsec = ((PlayerInfo*)(peer->data))->packetinsec + 1;
		}
	}
	else {
		((PlayerInfo*)(peer->data))->packetsec = (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count();
		((PlayerInfo*)(peer->data))->packetinsec = 0;
	}
}



void sendNothingHappened(ENetPeer* peer, int x, int y) {
	PlayerMoving data;
	data.netID = ((PlayerInfo*)(peer->data))->netID;
	data.packetType = 0x8;
	data.plantingTree = 0;
	data.netID = -1;
	data.x = x;
	data.y = y;
	data.punchX = x;
	data.punchY = y;
	SendPacketRaw(4, packPlayerMoving(&data), 56, 0, peer, ENET_PACKET_FLAG_RELIABLE);
}

bool isWorldOwner(ENetPeer* peer, WorldInfo* world) {
	return ((PlayerInfo*)(peer->data))->userID == world->ownerId;
}

void sendTileUpdate(int x, int y, int tile, int causedBy, ENetPeer* peer)
{

	if (tile > (coredatasize - 2)) return;
	bool isUndestroyable = false;
	bool isLock = false;
	bool isTree = false;
	PlayerMoving data;
	//data.packetType = 0x14;
	data.packetType = 0x3;

	//data.characterState = 0x924; // animation
	data.characterState = 0x0; // animation
	data.x = x;
	data.y = y;
	data.punchX = x;
	data.punchY = y;
	data.XSpeed = 0;
	data.YSpeed = 0;
	data.netID = causedBy;
	data.plantingTree = tile;

	WorldInfo *world = getPlyersWorld(peer);


	//if (getItemDef(tile).blockType == BlockTypes::CONSUMABLE) return;
	if (getItemDef(tile).blockType == BlockTypes::SEED) isTree = true;

	if (((PlayerInfo*)(peer->data))->currentWorld == "EXIT") return;
	if (world == NULL) return;
	int netID = ((PlayerInfo*)(peer->data))->netID;
	if (x<0 || y<0 || x>world->width || y>world->height) return;
	if (isTree) {
		//updateTreeVisuals(peer, tile, x, y, world->items[x + (y*world->width)].background, 2, 25, false, 0x00000000); // TODO
	}
	sendNothingHappened(peer, x, y);


	if (world->items[x + (y*world->width)].foreground == 1420 || world->items[x + (y*world->width)].foreground == 6214 && tile != 18) {
		if (isWorldOwner(peer, world)) {
			int c = getItemDef(tile).clothType;
			if (c == 0) {
				world->items[x + (y*world->width)].clothHead = tile;
			}
			else if (c == 7) {
				world->items[x + (y*world->width)].clothHair = tile;
			}
			else if (c == 4) {
				world->items[x + (y*world->width)].clothMask = tile;
			}
			else if (c == 8) {
				world->items[x + (y*world->width)].clothNeck = tile;
			}
			else if (c == 6) {
				world->items[x + (y*world->width)].clothBack = tile;
			}
			else if (c == 1) {
				world->items[x + (y*world->width)].clothShirt = tile;
			}
			else if (c == 2) {
				world->items[x + (y*world->width)].clothPants = tile;
			}
			else if (c == 3) {
				world->items[x + (y*world->width)].clothFeet = tile;
			}
			else if (c == 5) {
				world->items[x + (y*world->width)].clothHand = tile;
			}

			if (c != 10) {
				updateMannequin(peer, world->items[x + (y*world->width)].foreground, x, y, world->items[x + (y*world->width)].background, world->items[x + (y*world->width)].sign,
					world->items[x + (y*world->width)].clothHair, world->items[x + (y*world->width)].clothHead,
					world->items[x + (y*world->width)].clothMask, world->items[x + (y*world->width)].clothHand, world->items[x + (y*world->width)].clothNeck,
					world->items[x + (y*world->width)].clothShirt, world->items[x + (y*world->width)].clothPants, world->items[x + (y*world->width)].clothFeet,
					world->items[x + (y*world->width)].clothBack, true, 0);
			}
		}
	}
	if (world->items[x + (y*world->width)].foreground == 2946 && tile != 18 && tile != 32) {
		if (((PlayerInfo*)(peer->data))->haveGrowId == true) {
			if (isWorldOwner(peer, world) || getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) > 2) {
				updateDisplayVisuals(peer, 2946, x, y, world->items[x + (y*world->width)].background, tile, true);
				world->items[x + (y*world->width)].displayBlock = tile;
			}
			else
			{
				Player::OnConsoleMessage(peer, "`oFor that you gotta `2own `othe world`w!``");
				Player::OnPlayPositioned(peer, "audio/punch_locked.wav", netID, false, NULL);
			}
		}
		return;
	}
	if (getItemDef(world->items[x + (y * world->width)].foreground).blockType == BlockTypes::SIGN || world->items[x + (y * world->width)].foreground == 1420 || world->items[x + (y * world->width)].foreground == 6214)
	{
		if (tile == 32) {

			if (x != 0)
			{
				((PlayerInfo*)(peer->data))->lastPunchX = x;
			}
			if (y != 0)
			{
				((PlayerInfo*)(peer->data))->lastPunchY = y;
			}

			if (isWorldOwner(peer, world))
			{
				GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`wEdit Sign``|left|20|\n\nadd_textbox|`oWhat would you like to write on this sign?|\nadd_text_input|sign|||100|\nend_dialog|signok|Cancel|OK|\n"));
				ENetPacket * packet = enet_packet_create(p.data,
					p.len,
					ENET_PACKET_FLAG_RELIABLE);
				enet_peer_send(peer, 0, packet);
				delete p.data;
			}
			else
			{
				Player::OnTalkBubble(peer, netID, "You need to own this world to edit the sign!", 2, true);
			}
		}
	}

	if (world->items[x + (y*world->width)].foreground == 2978) {
		// VEND UPDATE
		/*bool isPer = false;
		bool hasLocksInIt = true;
		TileExtra data;
		data.packetType = 0x5;
		data.characterState = 8;
		data.punchX = x;
		data.punchY = y;
		data.charStat = 13;
		data.blockid = 2978;
		data.backgroundid = world->items[x + (y*world->width)].background;
		data.visual = 0x00410000; //0x00210000
		if (hasLocksInIt == true) data.visual = 0x02410000;

		int n = 1796;
		string hex = "";
		{
			std::stringstream ss;
			ss << std::hex << n; // int decimal_value
			std::string res(ss.str());
			hex = res + "18";
		}
		int x;
		std::stringstream ss;
		ss << std::hex << hex;
		ss >> x;
		data.displayblock = x;

		int xes;
		{
			int wl = 2;
			string hex = "";
			{
				std::stringstream ss;
				ss << std::hex << wl; // int decimal_value
				std::string res(ss.str());
				hex = res + "00";
			}
			int x;
			std::stringstream ss;
			ss << std::hex << hex;
			ss >> x;

			xes = x;
		}

		BYTE* raw = NULL;
		if (isPer) {
			raw = packStuffVisual(&data, 16777215, -xes);
		}
		else
		{
			raw = packStuffVisual(&data, 0, xes);
		}
		SendPacketRaw2(192, raw, 102, 0, peer, ENET_PACKET_FLAG_RELIABLE);
		raw = NULL; // prevent memory leak*/
		Player::OnTalkBubble(peer, ((PlayerInfo*)(peer->data))->netID, "`oThis `wfeature `ois going to be available soon``", 0, true);
	}

	if (tile != 18 && tile != 32 && getItemDef(tile).blockType != BlockTypes::BACKGROUND && world->items[x + (y*world->width)].foreground != 0) {
		sendNothingHappened(peer, x, y);
		return;
	}

	if (getItemDef(tile).blockType == BlockTypes::LOCK && tile != 202 && tile != 204 && tile != 206 && tile != 4994)
	{
		if (((PlayerInfo*)(peer->data))->currentWorld == "PVP") return;
		if (((PlayerInfo*)(peer->data))->haveGrowId == true) {
			isLock = true;
		}
		else
		{
			Player::OnConsoleMessage(peer, "`oCreate an account before using the lock.``");
			Player::OnPlayPositioned(peer, "audio/punch_locked.wav", netID, false, NULL);
			return;
		}
	}

	if (!isSuperAdmin(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass))
	{
		if (world->items[x + (y*world->width)].foreground == 6 || world->items[x + (y*world->width)].foreground == 8 || world->items[x + (y*world->width)].foreground == 3760) {
			Player::OnTalkBubble(peer, netID, "`wIt's too strong to break.``", 2, true);
			Player::OnPlayPositioned(peer, "audio/punch_locked.wav", netID, false, NULL);
			return;
		}
		if (tile == 6 || tile == 8 || tile == 3760 || tile == 6864) {
			Player::OnTalkBubble(peer, netID, "`wIt's too heavy to place.``", 2, true);
			Player::OnPlayPositioned(peer, "audio/punch_locked.wav", netID, false, NULL);
			return;
		}
	}
	if (world->name == "ADMIN" && !getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass))
	{
		if (world->items[x + (y*world->width)].foreground == 758)
			sendRoulete(peer, x, y);
		return;
	}
	if (world->name != "ADMIN") {
		if (world->owner != "") {
			if (((PlayerInfo*)(peer->data))->userID == world->ownerId || getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) > 2) {
				// WE ARE GOOD TO GO
				if (tile == 32) {
					if (world->items[x + (y*world->width)].foreground == 3832) { // stuff weather dialog
						if (x != 0)
						{
							((PlayerInfo*)(peer->data))->lastPunchX = x;
						}
						if (y != 0)
						{
							((PlayerInfo*)(peer->data))->lastPunchY = y;
						}
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`wStuff Weather Machine``|left|3832|\nadd_item_picker|stuffitem|Edit Item|Choose any item you want to pick|\nadd_spacer|small|\nadd_text_input|gravity|Gravity Value||4|\nadd_spacer|small|\nadd_quick_exit|\nend_dialog|stuff|Nevermind||"));
						ENetPacket * packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);
						delete p.data;
					}
					if (getItemDef(world->items[x + (y*world->width)].foreground).blockType == BlockTypes::LOCK)
					{
						((PlayerInfo*)(peer->data))->lastPunchX = x;
						((PlayerInfo*)(peer->data))->lastPunchY = y;
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\nadd_label_with_icon|big|`wEdit World Lock``|left|242|\nadd_label|small|`wAccess list:``|left\nadd_spacer|small|\nadd_label|small|Currently, you're the only one with access.``|left\nadd_spacer|small|\nadd_player_picker|playerNetID|`wAdd``|\nadd_checkbox|checkbox_public|Allow anyone to Build and Break|0\nadd_checkbox|checkbox_disable_music|Disable Custom Music Blocks|0\nadd_text_input|tempo|Music BPM|100|3|\nadd_checkbox|checkbox_disable_music_render|Make Custom Music Blocks invisible|noflags|0|0|\nend_dialog|lock_edit|Cancel|OK|")); //\nadd_button|getKey|Get World Key|noflags|0|0|
						ENetPacket * packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);
						delete p.data;
					}
				}
			}
			else if (world->isPublic)
			{
				if (getItemDef(world->items[x + (y*world->width)].foreground).blockType == BlockTypes::LOCK)
				{
					if (getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) < 3) {
						Player::OnPlayPositioned(peer, "audio/punch_locked.wav", netID, false, NULL);
						return;
					}
					else {
						if (getItemDef(world->items[x + (y*world->width)].foreground).blockType == BlockTypes::LOCK)
						{
							Player::OnPlayPositioned(peer, "audio/punch_locked.wav", netID, false, NULL);
						}
					}
				}
			}
			else {
				if (getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) < 3) {
					Player::OnPlayPositioned(peer, "audio/punch_locked.wav", netID, false, NULL);
					return;
				}
				else
				{
					if (getItemDef(world->items[x + (y*world->width)].foreground).blockType == BlockTypes::LOCK)
					{
						Player::OnPlayPositioned(peer, "audio/punch_locked.wav", netID, false, NULL);
					}
				}
			}
			if (isLock) {
				Player::OnPlayPositioned(peer, "audio/punch_locked.wav", netID, false, NULL);
				return;
			}
		}
	}
	if (tile == 32) {
		// TODO
		return;
	}
	if (tile == 822) {
		world->items[x + (y*world->width)].water = !world->items[x + (y*world->width)].water;
		//cout << "xd" << endl;
		float water = 125.0f;
		TileExtra data;
		data.packetType = 0x5;
		data.characterState = 8;
		data.charStat = 8;
		data.blockid = 0;
		data.backgroundid = 0;
		data.visual = 0x04000000;
		data.punchX = x;
		data.punchY = y;
		data.netID = netID;
		SendPacketRaw2(192, packBlockVisual(&data), 100, 0, peer, ENET_PACKET_FLAG_RELIABLE);

		return;
	}
	if (tile == 3062)
	{
		world->items[x + (y*world->width)].fire = !world->items[x + (y*world->width)].fire;
		return;
	}
	if (tile == 1866)
	{
		world->items[x + (y*world->width)].glue = !world->items[x + (y*world->width)].glue;
		return;
	}
	ItemDefinition def;
	try {
		def = getItemDef(tile);
		if (def.clothType != ClothTypes::NONE) return;
	}
	catch (int e) {
		def.breakHits = 4;
		def.blockType = BlockTypes::UNKNOWN;
#ifdef TOTAL_LOG
		cout << "Ugh, unsupported item " << tile << endl;
#endif
	}

	if (tile == 544 || tile == 546 || tile == 4520 || tile == 382 || tile == 3116 || tile == 4520 || tile == 1792 || tile == 5666 || tile == 2994 || tile == 4368) return;
	if (tile == 5708 || tile == 5709 || tile == 5780 || tile == 5781 || tile == 5782 || tile == 5783 || tile == 5784 || tile == 5785 || tile == 5710 || tile == 5711 || tile == 5786 || tile == 5787 || tile == 5788 || tile == 5789 || tile == 5790 || tile == 5791 || tile == 6146 || tile == 6147 || tile == 6148 || tile == 6149 || tile == 6150 || tile == 6151 || tile == 6152 || tile == 6153 || tile == 5670 || tile == 5671 || tile == 5798 || tile == 5799 || tile == 5800 || tile == 5801 || tile == 5802 || tile == 5803 || tile == 5668 || tile == 5669 || tile == 5792 || tile == 5793 || tile == 5794 || tile == 5795 || tile == 5796 || tile == 5797 || tile == 544 || tile == 546 || tile == 4520 || tile == 382 || tile == 3116 || tile == 1792 || tile == 5666 || tile == 2994 || tile == 4368) return;
	if (tile == 1902 || tile == 1508 || tile == 428) return;
	if (tile == 4720 || tile == 4882 || tile == 6392 || tile == 3212 || tile == 4742 || tile == 3496 || tile == 3270 || tile == 4722) return;
	if (tile >= 7068) return;
	if (tile == 18) {
		if (world->items[x + (y*world->width)].background == 6864 && world->items[x + (y*world->width)].foreground == 0) return;
		if (world->items[x + (y*world->width)].background == 0 && world->items[x + (y*world->width)].foreground == 0) return;
		ItemDefinition brak;
		brak = getItemDef(world->items[x + (y * world->width)].foreground);

		//data.netID = -1;
		data.packetType = 0x8;
		data.plantingTree = 6;

		using namespace std::chrono;
		//if (world->items[x + (y*world->width)].foreground == 0) return;
		if ((duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count() - world->items[x + (y*world->width)].breakTime >= 4000)
		{
			world->items[x + (y*world->width)].breakTime = (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count();
			world->items[x + (y*world->width)].breakLevel = 4; // TODO
			if (world->items[x + (y*world->width)].foreground == 758)
				sendRoulete(peer, x, y);
		}
		else
			if (y < world->height && world->items[x + (y * world->width)].breakLevel + 4 >= brak.breakHits * 4) { // TODO

				data.packetType = 0x3;// 0xC; // 0xF // World::HandlePacketTileChangeRequest
				data.netID = causedBy;
				data.plantingTree = 18;
				int brokentile = world->items[x + (y*world->width)].foreground;
				if (((PlayerInfo*)(peer->data))->currentWorld != "EXIT") {
					if (getItemDef(brokentile).blockType == BlockTypes::LOCK) {
						if (getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) < 2) {
							Player::OnNameChanged(peer, ((PlayerInfo*)(peer->data))->netID, "`0`0" + ((PlayerInfo*)(peer->data))->displayNamebackup);
						}
						Player::SendTilePickup(peer, brokentile, ((PlayerInfo*)(peer->data))->netID, (float)x, (float)y, ((PlayerInfo*)(peer->data))->droppeditemcount, 1);
						ENetPeer * currentPeer;

						for (currentPeer = server->peers;
							currentPeer < &server->peers[server->peerCount];
							++currentPeer)
						{
							if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
								continue;
							if (isHere(peer, currentPeer)) {
								Player::OnConsoleMessage(currentPeer, "`w" + ((PlayerInfo*)(peer->data))->currentWorld + " `ohas had it's `wlock `oremoved.");
							}
						}
					}
				}
				//Player::SendTileAnimation(peer, x, y, causedBy, world->items[x + (y*world->width)].foreground);

				world->items[x + (y*world->width)].breakLevel = 0;
				if (brokentile != 0)
				{
					if (getItemDef(brokentile).blockType == BlockTypes::LOCK && brokentile != 4994 && brokentile != 202 && brokentile != 204 && brokentile != 206)
					{
						world->owner = "";
						world->isPublic = false;
					}
					if (brokentile == 410 || brokentile == 1832 || brokentile == 1770) {
						int x1 = 0;
						int y1 = 0;
						for (int i = 0; i < world->width * world->height; i++)
						{
							if (world->items[i].foreground == 6) {
								x1 = (i % world->width) * 32;
								y1 = (i / world->width) * 32;
								//world->items[i].foreground = 8;
							}
						}
						ENetPeer * currentPeer;

						for (currentPeer = server->peers;
							currentPeer < &server->peers[server->peerCount];
							++currentPeer)
						{
							if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
								continue;
							if (isHere(peer, currentPeer)) {
								if (((PlayerInfo*)(currentPeer->data))->respawnX != 0 && ((PlayerInfo*)(currentPeer->data))->respawnY != 0) {
									if (((PlayerInfo*)(currentPeer->data))->respawnX / 32 == x && ((PlayerInfo*)(currentPeer->data))->respawnY / 32 == y) {
										((PlayerInfo*)(currentPeer->data))->respawnX = x1;
										((PlayerInfo*)(currentPeer->data))->respawnY = y1;
										Player::SetRespawnPos(currentPeer, x1 / 32, (world->width * (y1 / 32)), ((PlayerInfo*)(currentPeer->data))->netID);
									}
								}
							}
						}
					}

					world->items[x + (y*world->width)].foreground = 0;
					int gemval = ((PlayerInfo*)(peer->data))->gems + rand() % 6;
					((PlayerInfo*)(peer->data))->gems = gemval;
					Player::OnSetBux(peer, gemval, 0);
					if (brokentile == 6) {
						int x1 = 0;
						int y1 = 0;
						for (int i = 0; i < world->width * world->height; i++)
						{
							if (world->items[i].foreground == 6) {
								x1 = (i % world->width) * 32;
								y1 = (i / world->width) * 32;
								//world->items[i].foreground = 8;
							}
						}
						ENetPeer * currentPeer;

						for (currentPeer = server->peers;
							currentPeer < &server->peers[server->peerCount];
							++currentPeer)
						{
							if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
								continue;
							if (isHere(peer, currentPeer)) {
								if (((PlayerInfo*)(currentPeer->data))->respawnX != 0 && ((PlayerInfo*)(currentPeer->data))->respawnY != 0) {
									if (((PlayerInfo*)(currentPeer->data))->respawnX / 32 == x && ((PlayerInfo*)(currentPeer->data))->respawnY / 32 == y) {
										((PlayerInfo*)(currentPeer->data))->respawnX = x1;
										((PlayerInfo*)(currentPeer->data))->respawnY = y1;
										Player::SetRespawnPos(currentPeer, x1 / 32, (world->width * (y1 / 32)), ((PlayerInfo*)(currentPeer->data))->netID);
									}
								}
							}
						}
					}
				}
				else {
					data.plantingTree = 18;
					world->items[x + (y*world->width)].background = 0;
					int gemval = ((PlayerInfo*)(peer->data))->gems + rand() % 6;
					((PlayerInfo*)(peer->data))->gems = gemval;
					Player::OnSetBux(peer, gemval, 0);
				}

			}
			else
				if (y < world->height)
				{
					world->items[x + (y*world->width)].breakTime = (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count();
					world->items[x + (y*world->width)].breakLevel += 4; // TODO
					if (world->items[x + (y*world->width)].foreground == 758)
						sendRoulete(peer, x, y);
				}

	}
	else {
		for (int i = 0; i < ((PlayerInfo*)(peer->data))->inventory.items.size(); i++)
		{
			if (((PlayerInfo*)(peer->data))->inventory.items.at(i).itemID == tile)
			{
				if ((unsigned int)((PlayerInfo*)(peer->data))->inventory.items.at(i).itemCount > 1)
				{
					((PlayerInfo*)(peer->data))->inventory.items.at(i).itemCount--;
				}
				else {
					((PlayerInfo*)(peer->data))->inventory.items.erase(((PlayerInfo*)(peer->data))->inventory.items.begin() + i);

				}
			}
		}
		if (def.blockType == BlockTypes::BACKGROUND)
		{
			world->items[x + (y*world->width)].background = tile;
		}
		else {
			if (tile == 6) {
				int x1 = 0;
				int y1 = 0;
				for (int i = 0; i < world->width * world->height; i++)
				{
					if (world->items[i].foreground == 6) {
						x1 = (i % world->width) * 32;
						y1 = (i / world->width) * 32;
						//world->items[i].foreground = 8;
					}
				}
				int bg = world->items[x + (y*world->width)].background;
				ENetPeer * currentPeer;
				for (currentPeer = server->peers;
					currentPeer < &server->peers[server->peerCount];
					++currentPeer)
				{
					if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
						continue;
					if (isHere(peer, currentPeer)) {
						if (((PlayerInfo*)(currentPeer->data))->respawnX == x1 && ((PlayerInfo*)(currentPeer->data))->respawnY == y1) {
							((PlayerInfo*)(currentPeer->data))->respawnX = (x * 32);
							((PlayerInfo*)(currentPeer->data))->respawnY = (y * 32);
							//updateDoor(currentPeer, bg, 6, x, y, "EXIT");
						}
					}
				}
			}
			world->items[x + (y*world->width)].foreground = tile;
			if (isLock) {

				int netID = ((PlayerInfo*)(peer->data))->netID;
				world->owner = ((PlayerInfo*)(peer->data))->displayName;
				world->ownerId = ((PlayerInfo*)(peer->data))->userID;
				world->isPublic = false;

				auto p = packetEnd(appendString(appendString(createPacket(), "OnPlayPositioned"), "audio/use_lock.wav")); // ((PlayerInfo*)(server->peers[i].data))->tankIDName
				memcpy(p.data + 8, &netID, 4);
				ENetPacket * packet = enet_packet_create(p.data,
					p.len,
					ENET_PACKET_FLAG_RELIABLE);

				Player::OnConsoleMessage(peer, "`3[`w" + world->name + " `ohas been World Locked by `2" + ((PlayerInfo*)(peer->data))->displayName + "`3]``");
				Player::OnPlayPositioned(peer, "", 0, true, packet);
				Player::OnNameChanged(peer, ((PlayerInfo*)(peer->data))->netID, "`0`0`2" + ((PlayerInfo*)(peer->data))->displayName);
				delete p.data;

			}
		}


		world->items[x + (y*world->width)].breakLevel = 0;

	}

	ENetPeer * currentPeer;

	for (currentPeer = server->peers;
		currentPeer < &server->peers[server->peerCount];
		++currentPeer)
	{
		if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
			continue;
		if (isHere(peer, currentPeer))
			SendPacketRaw(4, packPlayerMoving(&data), 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);

		//cout << "Tile update at: " << data2->punchX << "x" << data2->punchY << endl;
	}
	if (isLock) {
		ENetPeer* currentPeer;

		for (currentPeer = server->peers;
			currentPeer < &server->peers[server->peerCount];
			++currentPeer)
		{
			if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
				continue;
			if (isHere(peer, currentPeer)) {
				sendTileData(currentPeer, x, y, 0x10, tile, world->items[x + (y*world->width)].background, lockTileDatas(0x20, ((PlayerInfo*)(peer->data))->userID, 0, 0, false, 100));
			}
		}
	}
}



void sendPlayerLeave(ENetPeer* peer, PlayerInfo* player)
{
	ENetPeer * currentPeer;
	GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnRemove"), "netID|" + std::to_string(player->netID) + "\n")); // ((PlayerInfo*)(server->peers[i].data))->tankIDName
	GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`5<`w" + player->displayName + "`` left, `w" + std::to_string(getPlayersCountInWorld(player->currentWorld) - 1) + "`` others here>``"));
	for (currentPeer = server->peers;
		currentPeer < &server->peers[server->peerCount];
		++currentPeer)
	{
		if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
			continue;
		if (isHere(peer, currentPeer)) {
			{


				if (peer != currentPeer)
				{
					ENetPacket * packet = enet_packet_create(p.data,
						p.len,
						ENET_PACKET_FLAG_RELIABLE);
					enet_peer_send(currentPeer, 0, packet);
					//Player::OnTalkBubble(currentPeer, player->netID, "`5<`w" + player->displayName + "`` left, `w" + std::to_string(getPlayersCountInWorld(player->currentWorld)) + "`` others here>``", 0, true);
				}

			}
			{
				if (((PlayerInfo*)(peer->data))->isinv == false) {
					int respawnTimeout = 150;
					int deathFlag = 0x19;
					memcpy(p2.data + 24, &respawnTimeout, 4);
					memcpy(p2.data + 56, &deathFlag, 4);
					ENetPacket * packet2 = enet_packet_create(p2.data,
						p2.len,
						ENET_PACKET_FLAG_RELIABLE);
					enet_peer_send(currentPeer, 0, packet2);
				}
			}
		}
	}
	delete p.data;
	delete p2.data;
}



void sendChatMessage(ENetPeer* peer, int netID, string message)
{
	for (char c : message)
		if (c < 0x18 || std::all_of(message.begin(), message.end(), isspace))
		{
			return;
		}

	ENetPeer * currentPeer;
	string name = "";
	for (currentPeer = server->peers;
		currentPeer < &server->peers[server->peerCount];
		++currentPeer)
	{
		if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
			continue;
		if (((PlayerInfo*)(currentPeer->data))->netID == netID)
			name = ((PlayerInfo*)(currentPeer->data))->displayName;

	}

	GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`o<`w" + name + "`o> " + message));
	GamePacket p2 = packetEnd(appendIntx(appendString(appendIntx(appendString(createPacket(), "OnTalkBubble"), netID), message), 0));
	if (((PlayerInfo*)(peer->data))->isNicked == false) {
		if (getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 3) {
			p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`o<`w" + name + "`o> `~" + message));
			p2 = packetEnd(appendIntx(appendString(appendIntx(appendString(createPacket(), "OnTalkBubble"), netID), "`~" + message), 0));
		}
		else if (getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) > 3) {
			p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`o<`w" + name + "`o> `5" + message));
			p2 = packetEnd(appendIntx(appendString(appendIntx(appendString(createPacket(), "OnTalkBubble"), netID), "`5" + message), 0));
		}
	}
	for (currentPeer = server->peers;
		currentPeer < &server->peers[server->peerCount];
		++currentPeer)
	{
		if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
			continue;
		if (isHere(peer, currentPeer))
		{

			ENetPacket * packet = enet_packet_create(p.data,
				p.len,
				ENET_PACKET_FLAG_RELIABLE);

			enet_peer_send(currentPeer, 0, packet);

			//enet_host_flush(server);

			ENetPacket * packet2 = enet_packet_create(p2.data,
				p2.len,
				ENET_PACKET_FLAG_RELIABLE);
			enet_peer_send(currentPeer, 0, packet2);

			//enet_host_flush(server);
		}
	}
	delete p.data;
	delete p2.data;
}

void sendWho(ENetPeer* peer)
{
	ENetPeer * currentPeer;
	string name = "";
	for (currentPeer = server->peers;
		currentPeer < &server->peers[server->peerCount];
		++currentPeer)
	{
		if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
			continue;
		if (isHere(peer, currentPeer))
		{
			if (((PlayerInfo*)(currentPeer->data))->isinv)
				continue;
			GamePacket p2 = packetEnd(appendIntx(appendString(appendIntx(appendString(createPacket(), "OnTalkBubble"), ((PlayerInfo*)(currentPeer->data))->netID), ((PlayerInfo*)(currentPeer->data))->displayName), 1));
			ENetPacket * packet2 = enet_packet_create(p2.data,
				p2.len,
				ENET_PACKET_FLAG_RELIABLE);

			enet_peer_send(peer, 0, packet2);
			delete p2.data;
			//enet_host_flush(server);
		}
	}
}

void sendExit(ENetPeer* peer) {

	if (!((PlayerInfo*)(peer->data))->isIn) return;
	vector<WorldInfo> worlds = worldDB.getRandomWorlds();
	string worldOffers = "default|";
	if (worlds.size() > 0) {
		worldOffers += worlds[0].name;
	}

	worldOffers += "\nadd_button|`2PVP`w/`2FFA``|PVP|1|9526341481|\n";
	for (int i = 0; i < worlds.size(); i++) {
		worldOffers += "add_floater|" + worlds[i].name + "|" + std::to_string(getPlayersCountInWorld(worlds[i].name)) + "|0.55|3529161471\n";
	}
	//GamePacket p3 = packetEnd(appendString(appendString(createPacket(), "OnRequestWorldSelectMenu"), "default|GO FOR IT\nadd_button|Showing: `wFake Worlds``|_catselect_|0.6|3529161471|\nadd_floater|Subscribe|5|0.55|3529161471\nadd_floater|Growtopia|4|0.52|4278190335\nadd_floater|Noobs|150|0.49|3529161471\nadd_floater|...|3|0.49|3529161471\nadd_floater|`6:O :O :O``|2|0.46|3529161471\nadd_floater|SEEMS TO WORK|2|0.46|3529161471\nadd_floater|?????|1|0.43|3529161471\nadd_floater|KEKEKEKEK|13|0.7|3417414143\n"));
	//for (int i = 0; i < p.len; i++) cout << (int)*(p.data + i) << " ";
	GamePacket p3 = packetEnd(appendString(appendString(createPacket(), "OnRequestWorldSelectMenu"), worldOffers));
	int respawnTimeout = 150;
	int deathFlag = 0x19;
	memcpy(p3.data + 24, &respawnTimeout, 4);
	memcpy(p3.data + 56, &deathFlag, 4);
	ENetPacket * packet3 = enet_packet_create(p3.data,
		p3.len,
		ENET_PACKET_FLAG_RELIABLE);
	enet_peer_send(peer, 0, packet3);
	delete p3.data;
}

void sendWorldOffers(ENetPeer* peer)
{
	if (!((PlayerInfo*)(peer->data))->isIn) return;
	vector<WorldInfo> worlds = worldDB.getRandomWorlds();
	string worldOffers = "default|";
	if (worlds.size() > 0) {
		worldOffers += worlds[0].name;
	}

	worldOffers += "\nadd_button|`2PVP`w/`2FFA``|PVP|1|9526341481|\n";
	for (int i = 0; i < worlds.size(); i++) {
		worldOffers += "add_floater|" + worlds[i].name + "|" + std::to_string(getPlayersCountInWorld(worlds[i].name)) + "|0.55|3529161471\n";
	}
	//GamePacket p3 = packetEnd(appendString(appendString(createPacket(), "OnRequestWorldSelectMenu"), "default|GO FOR IT\nadd_button|Showing: `wFake Worlds``|_catselect_|0.6|3529161471|\nadd_floater|Subscribe|5|0.55|3529161471\nadd_floater|Growtopia|4|0.52|4278190335\nadd_floater|Noobs|150|0.49|3529161471\nadd_floater|...|3|0.49|3529161471\nadd_floater|`6:O :O :O``|2|0.46|3529161471\nadd_floater|SEEMS TO WORK|2|0.46|3529161471\nadd_floater|?????|1|0.43|3529161471\nadd_floater|KEKEKEKEK|13|0.7|3417414143\n"));
	//for (int i = 0; i < p.len; i++) cout << (int)*(p.data + i) << " ";
	GamePacket p3 = packetEnd(appendString(appendString(createPacket(), "OnRequestWorldSelectMenu"), worldOffers));

	ENetPacket * packet3 = enet_packet_create(p3.data,
		p3.len,
		ENET_PACKET_FLAG_RELIABLE);
	enet_peer_send(peer, 0, packet3);
	delete p3.data;
	//enet_host_flush(server);
}

void sendWorld2(ENetPeer* peer, string* world) {
	string packet;
	packet.resize(60);
	packet[0] = 0x04;
	packet[4] = 0x04;
	packet[16] = 0x08;
	STRINT(packet, 56) = world->length();

	*world = packet + *world;
	ENetPacket* epacket = enet_packet_create(world->c_str(),
		world->length(),
		ENET_PACKET_FLAG_RELIABLE);
	enet_peer_send(peer, 0, epacket);
}


void sendWorld(ENetPeer* peer, WorldInfo* worldInfo)
{
	
	// LOADING DROPPED ITEMS
	/*DroppedItem itemDropped;
	itemDropped.id = 0;
	itemDropped.count = 0;
	itemDropped.x = 0;
	itemDropped.y = 0;
	itemDropped.uid = 0;*/
	// TODO DROPPING ITEMS!!!!!!!!!!!!!!!!
	/*if (worldInfo->dropSized == false) {
		worldInfo->droppedItems.resize(1024000);
		for (int i = 0; i < 65536; i++) worldInfo->droppedItems.push_back(itemDropped);
		worldInfo->dropSized = true;
	}*/


	int zero = 0;
	((PlayerInfo*)(peer->data))->droppeditemcount = 0;
#ifdef TOTAL_LOG
	cout << "Entering a world..." << endl;
#endif
	((PlayerInfo*)(peer->data))->joinClothesUpdated = false;
	string asdf = "0400000004A7379237BB2509E8E0EC04F8720B050000000000000000FBBB0000010000007D920100FDFDFDFD04000000040000000000000000000000070000000000"; // 0400000004A7379237BB2509E8E0EC04F8720B050000000000000000FBBB0000010000007D920100FDFDFDFD04000000040000000000000000000000080000000000000000000000000000000000000000000000000000000000000048133A0500000000BEBB0000070000000000
	string worldName = worldInfo->name;
	int xSize = worldInfo->width;
	int ySize = worldInfo->height;
	int square = xSize * ySize;
	__int16 nameLen = (__int16)worldName.length();
	int payloadLen = asdf.length() / 2;
	int dataLen = payloadLen + 2 + nameLen + 12 + (square * 8) + 4 + 100;
	int offsetData = dataLen - 100;
	int allocMem = payloadLen + 2 + nameLen + 12 + (square * 8) + 4 + 16000 + 100 + (worldInfo->droppedCount * 20);
	BYTE* data = new BYTE[allocMem];
	memset(data, 0, allocMem);
	for (int i = 0; i < asdf.length(); i += 2)
	{
		char x = ch2n(asdf[i]);
		x = x << 4;
		x += ch2n(asdf[i + 1]);
		memcpy(data + (i / 2), &x, 1);
	}

	__int16 item = 0;
	int smth = 0;
	for (int i = 0; i < square * 8; i += 4) memcpy(data + payloadLen + i + 14 + nameLen, &zero, 4);
	for (int i = 0; i < square * 8; i += 8) memcpy(data + payloadLen + i + 14 + nameLen, &item, 2);
	memcpy(data + payloadLen, &nameLen, 2);
	memcpy(data + payloadLen + 2, worldName.c_str(), nameLen);
	memcpy(data + payloadLen + 2 + nameLen, &xSize, 4);
	memcpy(data + payloadLen + 6 + nameLen, &ySize, 4);
	memcpy(data + payloadLen + 10 + nameLen, &square, 4);
	BYTE* blockPtr = data + payloadLen + 14 + nameLen;

	int sizeofblockstruct = 8;


	for (int i = 0; i < square; i++) {

		int tile = worldInfo->items[i].foreground;
		sizeofblockstruct = 8;


		//if (world->items[x + (y*world->width)].foreground == 242 or world->items[x + (y*world->width)].foreground == 2408 or world->items[x + (y*world->width)].foreground == 5980 or world->items[x + (y*world->width)].foreground == 2950 or world->items[x + (y*world->width)].foreground == 5814 or world->items[x + (y*world->width)].foreground == 4428 or world->items[x + (y*world->width)].foreground == 1796 or world->items[x + (y*world->width)].foreground == 4802 or world->items[x + (y*world->width)].foreground == 4994 or world->items[x + (y*world->width)].foreground == 5260 or world->items[x + (y*world->width)].foreground == 7188)
		if (tile == 6) {
			int type = 0x00010000;
			memcpy(blockPtr, &tile, 2);
			memcpy(blockPtr + 4, &type, 4);
			BYTE btype = 1;
			memcpy(blockPtr + 8, &btype, 1);

			string doorText = "EXIT";
			const char* doorTextChars = doorText.c_str();
			short length = (short)doorText.size();
			memcpy(blockPtr + 9, &length, 2);
			memcpy(blockPtr + 11, doorTextChars, length);
			sizeofblockstruct += 4 + length;
			dataLen += 4 + length; // it's already 8.

		}
		else if (getItemDef(tile).blockType == BlockTypes::SIGN || tile == 1420 || tile == 6124) {
			int type = 0x00010000;
			memcpy(blockPtr, &worldInfo->items[i].foreground, 2);
			memcpy(blockPtr + 4, &type, 4);
			BYTE btype = 2;
			memcpy(blockPtr + 8, &btype, 1);
			string signText = worldInfo->items[i].sign;
			const char* signTextChars = signText.c_str();
			short length = (short)signText.size();
			memcpy(blockPtr + 9, &length, 2);
			memcpy(blockPtr + 11, signTextChars, length);
			int minus1 = -1;
			memcpy(blockPtr + 11 + length, &minus1, 4);
			sizeofblockstruct += 3 + length + 4;
			dataLen += 3 + length + 4; // it's already 8.
		}
		else if (tile == 2946) {
			int type = 0x00010000;
			memcpy(blockPtr, &worldInfo->items[i].foreground, 2);
			memcpy(blockPtr + 4, &type, 4);
			BYTE btype = 0x17;
			memcpy(blockPtr + 8, &btype, 1);
			int item = worldInfo->items[i].displayBlock;
			memcpy(blockPtr + 9, &item, 4);
			sizeofblockstruct += 5;
			dataLen += 5;

		}
		else if (tile == 3832) {
			int type = 0x00010000;
			memcpy(blockPtr, &worldInfo->items[i].foreground, 2);
			memcpy(blockPtr + 4, &type, 4);
			BYTE btype = 0x31;
			memcpy(blockPtr + 8, &btype, 1);


			short flags = 0;
			int item = worldInfo->items[i].displayBlock;
			int gravity = worldInfo->items[i].gravity;
			flags = 3;

			memcpy(blockPtr + 9, &item, 4);
			memcpy(blockPtr + 13, &gravity, 4);
			memcpy(blockPtr + 17, &flags, 2);
			sizeofblockstruct += 10;
			dataLen += 10;
		}
		else if (getItemDef(tile).blockType == BlockTypes::LOCK && tile != 4994 && tile != 202 && tile != 204 && tile != 206)
		{

			int type = 0x00000000;
			type |= 0x00010000;
			int adminCount = 1;
			int ownerID = worldInfo->ownerId;
			// int admins[...]
			int szExtra = 10 + adminCount * 4;

			memset(blockPtr + 8, 0, szExtra);
			BYTE btype = 0x3;
			BYTE o = 0x1;
			memcpy(blockPtr, &worldInfo->items[i].foreground, 2);
			memcpy(blockPtr + 4, &type, 4);
			memcpy(blockPtr + 8, &btype, 1);
			memcpy(blockPtr + 8 + 2, &ownerID, 4);
			memcpy(blockPtr + 8 + 6, &adminCount, 1);
			memcpy(blockPtr + 8 + 10, &o, 1);

			sizeofblockstruct += szExtra;
			dataLen += szExtra;

		}



		else if ((worldInfo->items[i].foreground == 0) || (worldInfo->items[i].foreground == 2) || (worldInfo->items[i].foreground == 8) || (worldInfo->items[i].foreground == 100) || (worldInfo->items[i].foreground == 4))
		{

			memcpy(blockPtr, &worldInfo->items[i].foreground, 2);
			int type = 0x00000000;

			// type 1 = locked
			if (worldInfo->items[i].activated)
				type |= 0x00200000;
			if (worldInfo->items[i].water)
				type |= 0x04000000;
			if (worldInfo->items[i].glue)
				type |= 0x08000000;
			if (worldInfo->items[i].fire)
				type |= 0x10000000;
			if (worldInfo->items[i].red)
				type |= 0x20000000;
			if (worldInfo->items[i].green)
				type |= 0x40000000;
			if (worldInfo->items[i].blue)
				type |= 0x80000000;

			// int type = 0x04000000; = water
			// int type = 0x08000000 = glue
			// int type = 0x10000000; = fire
			// int type = 0x20000000; = red color
			// int type = 0x40000000; = green color
			// int type = 0x80000000; = blue color


			memcpy(blockPtr + 4, &type, 4);
			/*if (worldInfo->items[i].foreground % 2)
			{
				blockPtr += 6;
			}*/
		}
		else
		{
			memcpy(blockPtr, &zero, 2);
		}
		memcpy(blockPtr + 2, &worldInfo->items[i].background, 2);
		blockPtr += sizeofblockstruct;

	}

	/*int increase = 20;
//TODO

	int inc = 20;
	memcpy(blockPtr, &worldInfo->droppedCount, 4);
	memcpy(blockPtr + 4, &worldInfo->droppedCount, 4);

	for (int i = 0; i < worldInfo->droppedCount; i++) {

		memcpy(blockPtr + inc - 12, &worldInfo->droppedItems.at(i).id, 2);
		memcpy(blockPtr + inc - 10, &worldInfo->droppedItems.at(i).x, 4);
		memcpy(blockPtr + inc - 6, &worldInfo->droppedItems.at(i).y, 4);
		memcpy(blockPtr + inc - 2, &worldInfo->droppedItems.at(i).count, 2);
		memcpy(blockPtr + inc, &i, 4);
		inc += 16;

	}
	blockPtr += inc;
	dataLen += inc;*/

	//((PlayerInfo*)(peer->data))->droppeditemcount = worldInfo->droppedCount;
	offsetData = dataLen - 100;

	//              0       1       2       3       4       5       6       7       8       9      10     11      12      13      14
	string asdf2 = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
	BYTE* data2 = new BYTE[101];
	memcpy(data2 + 0, &zero, 4);
	for (int i = 0; i < asdf2.length(); i += 2)
	{
		char x = ch2n(asdf2[i]);
		x = x << 4;
		x += ch2n(asdf2[i + 1]);
		memcpy(data2 + (i / 2), &x, 1);
	}
	int weather = worldInfo->weather;
	memcpy(data2 + 4, &weather, 4);

	memcpy(data + offsetData, data2, 100);


	//cout << dataLen << " <- dataLen allocMem -> " << allocMem << endl;
	memcpy(data + dataLen - 4, &smth, 4);
	ENetPacket * packet2 = enet_packet_create(data,
		dataLen,
		ENET_PACKET_FLAG_RELIABLE);
	enet_peer_send(peer, 0, packet2);
	//enet_host_flush(server);
	for (int i = 0; i < square; i++) {
		if ((worldInfo->items[i].foreground == 0) || (getItemDef(worldInfo->items[i].foreground).blockType) == BlockTypes::SIGN || worldInfo->items[i].foreground == 1420 || worldInfo->items[i].foreground == 6214 || (worldInfo->items[i].foreground == 3832) || (worldInfo->items[i].foreground == 2946) || (worldInfo->items[i].foreground == 6) || (worldInfo->items[i].foreground == 242) || (worldInfo->items[i].foreground == 1796) || (worldInfo->items[i].foreground == 4) || (worldInfo->items[i].foreground == 2) || (worldInfo->items[i].foreground == 8) || (worldInfo->items[i].foreground == 100))
			; // nothing
		else
		{
			PlayerMoving data;
			//data.packetType = 0x14;
			data.packetType = 0x3;

			//data.characterState = 0x924; // animation
			data.characterState = 0x0; // animation
			data.x = i % worldInfo->width;
			data.y = i / worldInfo->height;
			data.punchX = i % worldInfo->width;
			data.punchY = i / worldInfo->width;
			data.XSpeed = 0;
			data.YSpeed = 0;
			data.netID = -1;
			data.plantingTree = worldInfo->items[i].foreground;
			SendPacketRaw(4, packPlayerMoving(&data), 56, 0, peer, ENET_PACKET_FLAG_RELIABLE);

			//int x = i % xSize, y = i / xSize;
			//UpdateVisualsForBlock(peer, false, x, y, worldInfo);
		}
	}
	string wname = worldInfo->name;
	((PlayerInfo*)(peer->data))->currentWorld = wname;
	Player::OnConsoleMessage(peer, "World `w" + wname + "`` entered.  There are `w" + to_string(getPlayersCountInWorld(wname) - 1) + "`` other people here, `w1337`` online.``");
	if (worldInfo->owner != "") Player::OnConsoleMessage(peer, "`5[`w" + wname + "`` `$World Locked`` by " + worldInfo->owner + " (`2ACCESS GRANTED``)`5]");
	Player::PlayAudio(peer, "audio/door_open.wav", 0);

	delete data;
}

void sendPlayerToPlayer(ENetPeer* peer, ENetPeer* otherpeer)
{
	{
		sendPlayerLeave(peer, (PlayerInfo*)(peer->data));
	}
	WorldInfo info = worldDB.get(((PlayerInfo*)(otherpeer->data))->currentWorld);
	sendWorld(peer, &info);

	int x = ((PlayerInfo*)(otherpeer->data))->x;
	int y = ((PlayerInfo*)(otherpeer->data))->y;
	GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnSpawn"), "spawn|avatar\nnetID|" + std::to_string(cId) + "\nuserID|" + std::to_string(((PlayerInfo*)(peer->data))->userID) + "\ncolrect|0|0|20|30\nposXY|" + std::to_string(x) + "|" + std::to_string(y) + "\nname|``" + ((PlayerInfo*)(peer->data))->displayName + "``\ncountry|" + ((PlayerInfo*)(peer->data))->country + "\ninvis|" + to_string(((PlayerInfo*)(peer->data))->isinv) + "\nmstate|" + to_string(((PlayerInfo*)(peer->data))->mstate) + "\nsmstate|" + to_string(((PlayerInfo*)(peer->data))->smstate) + "\ntype|local\n"));
	ENetPacket * packet = enet_packet_create(p.data,
		p.len,
		ENET_PACKET_FLAG_RELIABLE);
	enet_peer_send(peer, 0, packet);
	delete p.data;
	((PlayerInfo*)(peer->data))->netID = cId;
	onPeerConnect(peer);
	cId++;
	sendInventory(peer, ((PlayerInfo*)(peer->data))->inventory);
}

void joinPVP(ENetPeer* peer) {
	if (((PlayerInfo*)(peer->data))->isIn == false) return;
	WorldInfo info = worldDB.get("PVP");
	sendWorld(peer, &info);
	Player::OnAddNotification(peer, "`bBattle begins `wnow`o, `4FREE FOR ALL`w!``", "audio/race_start.wav", "interface/logo_188.rttex");
	match.playersInQueue--;
	match.playersInGame++;

	if (match.topOne == "") {
		match.topOne = ((PlayerInfo*)(peer->data))->displayName;
	}
	else if (match.topTwo == "") {
		match.topTwo = ((PlayerInfo*)(peer->data))->displayName;
	}
	else if (match.topThree == "") {
		match.topThree = ((PlayerInfo*)(peer->data))->displayName;
	}
	else if (match.topFour == "") {
		match.topFour = ((PlayerInfo*)(peer->data))->displayName;
	}
	else if (match.topFive == "") {
		match.topFive = ((PlayerInfo*)(peer->data))->displayName;
	}
	else
	{
		match.topSix = ((PlayerInfo*)(peer->data))->displayName;
	}

	((PlayerInfo*)(peer->data))->isInGame = true;
	((PlayerInfo*)(peer->data))->isWaitingForMatch = false;
	int x = 3040;
	int y = 736;

	for (int j = 0; j < info.width*info.height; j++)
	{
		if (info.items[j].foreground == 6) {
			x = (j%info.width) * 32;
			y = (j / info.width) * 32;
		}
	}

	((PlayerInfo*)(peer->data))->respawnX = x;
	((PlayerInfo*)(peer->data))->respawnY = y;
	GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnSpawn"), "spawn|avatar\nnetID|" + std::to_string(cId) + "\nuserID|" + std::to_string(((PlayerInfo*)(peer->data))->userID) + "\ncolrect|0|0|20|30\nposXY|" + std::to_string(x) + "|" + std::to_string(y) + "\nname|``" + ((PlayerInfo*)(peer->data))->displayName + "``\ncountry|" + ((PlayerInfo*)(peer->data))->country + "\ninvis|0\nmstate|0\nsmstate|0\ntype|local\n"));
	//for (int i = 0; i < p.len; i++) cout << (int)*(p.data + i) << " ";
	ENetPacket * packet = enet_packet_create(p.data,
		p.len,
		ENET_PACKET_FLAG_RELIABLE);
	enet_peer_send(peer, 0, packet);
	//enet_host_flush(server);
	delete p.data;
	((PlayerInfo*)(peer->data))->netID = cId;
	onPeerConnect(peer);
	cId++;

	if (((PlayerInfo*)(peer->data))->loadedInventory == false) {
		PlayerInventory inventory;
		InventoryItem item;
		item.itemCount = 1;
		item.itemID = 18;
		inventory.items.push_back(item);
		item.itemID = 32;
		inventory.items.push_back(item);
		((PlayerInfo*)(peer->data))->inventory = inventory;
		((PlayerInfo*)(peer->data))->loadedInventory = true;
	}
	sendInventory(peer, ((PlayerInfo*)(peer->data))->inventory);
	//updateAllClothes(peer);

	Player::PlayAudio(peer, "audio/ogg/gtv3_survive_ends.ogg", 390000);
}

void joinWorld(ENetPeer* peer, string act) {
	/*if (configPort == 17093) {
	if (((PlayerInfo*)(peer->data))->isIn == false) return;
		//enet_peer_timeout(peer, 0, 0, 0);
	Player::OnConsoleMessage(peer, "`oWorld is not located in this subserver, sending you to subserver 2!");
		Player::OnSendToServer(peer, ((PlayerInfo*)(peer->data))->userID, ((PlayerInfo*)(peer->data))->userID, "127.0.0.1", 17094, act, 1);

		
	}*/
	if (((PlayerInfo*)(peer->data))->isBot == true) {
		enet_peer_disconnect_now(peer, 0);
	}
	try {
		if (act.length() > 24) {
			sendConsoleMsg(peer, "`4Sorry, but world names with more than 24 characters are not allowed!");
			((PlayerInfo*)(peer->data))->currentWorld = "EXIT";
			GamePacket p2 = packetEnd(appendIntx(appendString(createPacket(), "OnFailedToEnterWorld"), 1));
			ENetPacket* packet2 = enet_packet_create(p2.data,
				p2.len,
				ENET_PACKET_FLAG_RELIABLE);
			enet_peer_send(peer, 0, packet2);
			delete p2.data;
		}
		else {
			using namespace std::chrono;
			if (((PlayerInfo*)(peer->data))->lastJoinReq + 500 < (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count())
			{
				((PlayerInfo*)(peer->data))->lastJoinReq = (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count();
			}
			else {
				Player::OnConsoleMessage(peer, "`oSlow down when entering worlds, jeez!``");
				Player::OnFailedToEnterWorld(peer);
				return;
			}
			string upsd = act;
			std::transform(upsd.begin(), upsd.end(), upsd.begin(), ::toupper);
			if (upsd == "TEST") {
				Player::OnConsoleMessage(peer, "`4To reduce confusion, this is not a valid world name`w. `oTry another one`w?``");
				Player::OnFailedToEnterWorld(peer);
				return;
			}
			if (upsd == "PVP") {

				if (((PlayerInfo*)(peer->data))->isQueuing == false) {
					if (match.isMatchRunning == true) {
						Player::OnConsoleMessage(peer, "`4Game `wis `4currently running, enter soon!``");
						Player::OnFailedToEnterWorld(peer);
						return;
					}
					((PlayerInfo*)(peer->data))->isWaitingForMatch = true;
					((PlayerInfo*)(peer->data))->isQueuing = true;

					if (match.playersInQueue < 0) match.playersInQueue = 0;
					match.playersInQueue++;
					if (match.playersInQueue < 6) {
						Player::OnConsoleMessage(peer, "`wWaiting for players... (" + to_string(match.playersInQueue) + "/6)``");
						ENetPeer * currentPeer;
						for (currentPeer = server->peers;
							currentPeer < &server->peers[server->peerCount];
							++currentPeer)
						{
							if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
								continue;
							if (((PlayerInfo*)(currentPeer->data))->isQueuing == true) {
								Player::PlayAudio(currentPeer, "audio/success.wav", 100);
								Player::OnConsoleMessage(currentPeer, "`w" + ((PlayerInfo*)(peer->data))->displayName + " `ojoined the match! (" + to_string(match.playersInQueue) + "/6)");
							}
						}

					}
					else
					{

						WorldInfo info = worldDB.get("PVP");
						ENetPeer * currentPeer;
						for (currentPeer = server->peers;
							currentPeer < &server->peers[server->peerCount];
							++currentPeer)
						{
							if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
								continue;
							if (((PlayerInfo*)(currentPeer->data))->isQueuing) {
								((PlayerInfo*)(currentPeer->data))->isQueuing = false;
								joinPVP(currentPeer);
								//Player::OnCountdownStart(peer, ((PlayerInfo*)(peer->data))->netID, 390, 0);
							}
						}
						match.timePVPStarted = GetCurrentTimeInternalSeconds();
						match.playersInQueue = 0;
						match.isMatchRunning = true;
					}
					return;
				}
				//Player::PlayAudio(peer, "audio/ogg/gtv3_survive_ends.ogg", 870000);
			}



			WorldInfo info = worldDB.get(act);
			sendWorld(peer, &info);

			if (((PlayerInfo*)(peer->data))->haveGrowId) {
				if (info.owner == ((PlayerInfo*)(peer->data))->rawName) {
					if (getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) < 2) {
						((PlayerInfo*)(peer->data))->displayName = "`2" + ((PlayerInfo*)(peer->data))->displayName;
					}
				}
				else {
					if (getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) < 2) {
						((PlayerInfo*)(peer->data))->displayName = ((PlayerInfo*)(peer->data))->displayNamebackup;
					}
				}
			}

			//`2" + ((PlayerInfo*)(peer->data))->displayName


			int x = 3040;
			int y = 736;

			for (int j = 0; j < info.width*info.height; j++)
			{
				if (info.items[j].foreground == 6) {
					x = (j%info.width) * 32;
					y = (j / info.width) * 32;
				}
			}
			((PlayerInfo*)(peer->data))->respawnX = x;
			((PlayerInfo*)(peer->data))->respawnY = y;
			GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnSpawn"), "spawn|avatar\nnetID|" + std::to_string(cId) + "\nuserID|" + std::to_string(((PlayerInfo*)(peer->data))->userID) + "\ncolrect|0|0|20|30\nposXY|" + std::to_string(x) + "|" + std::to_string(y) + "\nname|``" + ((PlayerInfo*)(peer->data))->displayName + "``\ncountry|" + ((PlayerInfo*)(peer->data))->country + "\ninvis|" + to_string(((PlayerInfo*)(peer->data))->isinv) + "\nmstate|" + to_string(((PlayerInfo*)(peer->data))->mstate) + "\nsmstate|" + to_string(((PlayerInfo*)(peer->data))->smstate) + "\ntype|local\n"));
			//for (int i = 0; i < p.len; i++) cout << (int)*(p.data + i) << " ";
			ENetPacket * packet = enet_packet_create(p.data,
				p.len,
				ENET_PACKET_FLAG_RELIABLE);
			enet_peer_send(peer, 0, packet);
			//enet_host_flush(server);
			delete p.data;
			((PlayerInfo*)(peer->data))->netID = cId;
			onPeerConnect(peer);
			cId++;
			if (((PlayerInfo*)(peer->data))->loadedInventory == false) {
				PlayerInventory inventory;
				InventoryItem item;
				item.itemCount = 1;
				item.itemID = 18;
				inventory.items.push_back(item);
				item.itemID = 32;
				inventory.items.push_back(item);
				((PlayerInfo*)(peer->data))->inventory = inventory;
				((PlayerInfo*)(peer->data))->loadedInventory = true;
			}
			sendInventory(peer, ((PlayerInfo*)(peer->data))->inventory);



			/*int resx = 95;
			int resy = 23;*/

			/*for (int i = 0; i < world.width*world.height; i++)
			{
			if (world.items[i].foreground == 6) {
			resx = i%world.width;
			resy = i / world.width;
			}
			}

			GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "SetRespawnPos"), resx + (world.width*resy)));
			memcpy(p2.data + 8, &(((PlayerInfo*)(event.peer->data))->netID), 4);
			ENetPacket * packet2 = enet_packet_create(p2.data,
			p2.len,
			ENET_PACKET_FLAG_RELIABLE);
			enet_peer_send(peer, 0, packet);
			enet_host_flush(server);*/
		}
	}
	catch (int e) {
		if (e == 1) {
			((PlayerInfo*)(peer->data))->currentWorld = "EXIT";
			Player::OnFailedToEnterWorld(peer);
			GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "You have exited the world."));
			ENetPacket * packet = enet_packet_create(p.data,
				p.len,
				ENET_PACKET_FLAG_RELIABLE);
			enet_peer_send(peer, 0, packet);
			delete p.data;
			//enet_host_flush(server);
		}
		else if (e == 2) {
			((PlayerInfo*)(peer->data))->currentWorld = "EXIT";
			Player::OnFailedToEnterWorld(peer);
			GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "You have entered bad characters in the world name!"));
			ENetPacket * packet = enet_packet_create(p.data,
				p.len,
				ENET_PACKET_FLAG_RELIABLE);
			enet_peer_send(peer, 0, packet);
			delete p.data;
			//enet_host_flush(server);
		}
		else if (e == 3) {
			((PlayerInfo*)(peer->data))->currentWorld = "EXIT";
			Player::OnFailedToEnterWorld(peer);
			GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "Exit from what? Click back if you're done playing."));
			ENetPacket * packet = enet_packet_create(p.data,
				p.len,
				ENET_PACKET_FLAG_RELIABLE);
			enet_peer_send(peer, 0, packet);
			delete p.data;
			//enet_host_flush(server);
		}
		else {
			((PlayerInfo*)(peer->data))->currentWorld = "EXIT";
			Player::OnFailedToEnterWorld(peer);
			GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "I know this menu is magical and all, but it has its limitations! You can't visit this world!"));
			ENetPacket * packet = enet_packet_create(p.data,
				p.len,
				ENET_PACKET_FLAG_RELIABLE);
			enet_peer_send(peer, 0, packet);
			delete p.data;
			//enet_host_flush(server);
		}
	}
}

void setupQueue() {
	while (1) {
		Sleep(3000);
		ENetPeer * currentPeer;
		for (currentPeer = server->peers;
			currentPeer < &server->peers[server->peerCount];
			++currentPeer)
		{
			if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
				continue;
			if (((PlayerInfo*)(currentPeer->data))->isWaitingForMatch) {
				Player::OnAddNotification(currentPeer, "`2Still trying to find match...``", "audio/gong.wav", "interface/hommel.rttex");
			}
		}
	}
}

void Game() {
	while (1) {
		Sleep(10);
		if (match.isMatchRunning) {
			if (match.playersInGame < 2) {
				match.playersInGame = 0;
				ENetPeer * cPeer;
				for (cPeer = server->peers;
					cPeer < &server->peers[server->peerCount];
					++cPeer)
				{
					if (cPeer->state != ENET_PEER_STATE_CONNECTED)
						continue;
					if (((PlayerInfo*)(cPeer->data))->isInGame) {
						Player::OnConsoleMessage(cPeer, "`oNot enough players left, ending match...``");
						((PlayerInfo*)(cPeer->data))->isInGame = false;
						sendPlayerLeave(cPeer, ((PlayerInfo*)(cPeer->data)));
						((PlayerInfo*)(cPeer->data))->currentWorld = "EXIT";
						sendWorldOffers(cPeer);
						Player::PlayAudio(cPeer, "audio/door_shut.wav", 0);
					}
				}
				match.topOne = "";
				match.topTwo = "";
				match.topThree = "";
				match.topFour = "";
				match.topFive = "";
				match.topSix = "";
				match.playersInGame = 0;
				match.isMatchRunning = false;
			}
		}
	}
}

void manageGame() {
	while (1) {
		Sleep(10);
		if (match.isMatchRunning == true) {
			Sleep(420000);
			ENetPeer * currentPeer;
			for (currentPeer = server->peers;
				currentPeer < &server->peers[server->peerCount];
				++currentPeer)
			{
				if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
					continue;
				if (((PlayerInfo*)(currentPeer->data))->isInGame) {
					GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\nadd_label_with_icon|big|1st - " + match.topOne + "|left|6138|\nadd_label_with_icon|big|2nd - " + match.topTwo + "|left|7672|\nadd_label_with_icon|big|3rd - " + match.topThree + "|left|7336|\nadd_button|backtoexit|Back to EXIT|noflags|0|0|\n\nnend_dialog|pvprank||OK|"));
					ENetPacket * packet = enet_packet_create(p.data,
						p.len,
						ENET_PACKET_FLAG_RELIABLE);
					enet_peer_send(currentPeer, 0, packet);
					delete p.data;
				}
			}
			Sleep(12000);
			ENetPeer * cPeer;
			for (cPeer = server->peers;
				cPeer < &server->peers[server->peerCount];
				++cPeer)
			{
				if (cPeer->state != ENET_PEER_STATE_CONNECTED)
					continue;
				if (((PlayerInfo*)(cPeer->data))->isInGame) {
					((PlayerInfo*)(cPeer->data))->isInGame = false;
					sendPlayerLeave(cPeer, ((PlayerInfo*)(cPeer->data)));
					((PlayerInfo*)(cPeer->data))->currentWorld = "EXIT";
					sendWorldOffers(cPeer);
					Player::PlayAudio(cPeer, "audio/door_shut.wav", 0);
				}
			}
			match.topOne = "";
			match.topTwo = "";
			match.topThree = "";
			match.topFour = "";
			match.topFive = "";
			match.topSix = "";
			match.playersInGame = 0;
			match.isMatchRunning = false;
		}
	}
}


void sendAction(ENetPeer* peer, int netID, string action)
{
	ENetPeer * currentPeer;
	string name = "";
	GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnAction"), action));
	for (currentPeer = server->peers;
		currentPeer < &server->peers[server->peerCount];
		++currentPeer)
	{
		if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
			continue;
		if (isHere(peer, currentPeer)) {

			memcpy(p2.data + 8, &netID, 4);
			ENetPacket * packet2 = enet_packet_create(p2.data,
				p2.len,
				ENET_PACKET_FLAG_RELIABLE);

			enet_peer_send(currentPeer, 0, packet2);

			//enet_host_flush(server);
		}
	}
	delete p2.data;
}


// droping items WorldObjectMap::HandlePacket











//replaced X-to-close with a Ctrl+C exit
void exitHandler(int s) {
	saveAllWorlds();
	logs.close();
	exit(0);
}

std::ifstream::pos_type filesize(const char* filename)
{
	std::ifstream in(filename, std::ifstream::ate | std::ifstream::binary);
	return in.tellg();
}

bool has_only_digits(const string s) {
	return s.find_first_not_of("0123456789") == string::npos;
}
bool has_only_digits_wnegative(const string s) {
	return s.find_first_not_of("-0123456789") == string::npos;
}






void loadConfig() {
	/*inside config.json:
	{
	"port": 17091
	}
	*/


	std::ifstream ifs("config.json");
	if (ifs.is_open()) {
		json j;
		ifs >> j;
		ifs.close();
		try {
			configPort = j["port"].get<int>();

			cout << "Config loaded." << " Port: " << configPort << endl;
		}
		catch (...) {
			cout << "Invalid config." << endl;
		}
	}
	else {
		cout << "Config not found." << endl;
	}
}



/*
action|log
msg|`4UPDATE REQUIRED!`` : The `$V2.981`` update is now available for your device.  Go get it!  You'll need to install it before you can play online.
[DBG] Some text is here: action|set_url
url|http://ubistatic-a.akamaihd.net/0098/20180909/GrowtopiaInstaller.exe
label|Download Latest Version
	*/
	//Linux should not have any arguments in main function.
std::string string_to_hex(const std::string& input)
{
	static const char* const lut = "0123456789ABCDEF";
	size_t len = input.length();

	std::string output;
	output.reserve(2 * len);
	for (size_t i = 0; i < len; ++i)
	{
		const unsigned char c = input[i];
		output.push_back(lut[c >> 4]);
		output.push_back(lut[c & 15]);
	}
	return output;
}

void ServerInputPluginByplayingo()
{
	while (ServerInputPluginByplayingo)
	{
		std::string buffer;
		std::cin >> buffer;

		// example:
		if (buffer == "exit") // if exit is typed in server console:
		{
			// do stuff
			exit(0);
		}
		else if (buffer == "save") {
			saveAllWorlds();
		}
		else if (buffer == "online")
		{
			string x;


			ENetPeer* currentPeer;
			for (currentPeer = server->peers;
				currentPeer < &server->peers[server->peerCount];
				++currentPeer)
			{
				if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
					continue;


				x.append(((PlayerInfo*)(currentPeer->data))->rawName + " (" + to_string(((PlayerInfo*)(currentPeer->data))->adminLevel) + ")" + " (" + ((PlayerInfo*)(currentPeer->data))->charIP + ")" + ", ");
			}
			x = x.substr(0, x.length() - 2);

			cout << "[Console] Peers connected (includes mods) [format: (rawname) (adminlevel) (IP)]: " << x << endl;

		}
		else if (buffer == "kickall")
		{
			ENetPeer* currentPeer;
			for (currentPeer = server->peers;
				currentPeer < &server->peers[server->peerCount];
				++currentPeer)
			{
				if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
					continue;

				enet_peer_disconnect_later(currentPeer, 0);
				enet_peer_reset(currentPeer);
			}
			cout << "Kicked everyone out of server!" << endl;
		}
		else if (buffer == "help" || buffer == "?")
		{
			cout << "Operator commands: " << "help " << "kickall " << "save " << "reload" << "online " << "delete " << "maintenance " << "exit" << endl;
		}
		else if (buffer == "rebuildplayers") {
			using recursive_directory_iterator = experimental::filesystem::recursive_directory_iterator;
			int i = 0;
			for (const auto& dirEntry : recursive_directory_iterator("players")) {
				i++;
				std::ifstream ifs(dirEntry);
				if (ifs.is_open()) {
					json j;
					ifs >> j;
					int adminLevel = j["adminLevel"];
					string discord = j["discord"];
					string email = j["email"];
					string password = j["password"];
					string name = j["username"];

					std::ofstream o(dirEntry);
					if (!o.is_open()) {
						cout << GetLastError() << endl;
						_getch();
					}
					j["username"] = name;
					j["password"] = password;
					j["email"] = email;
					j["discord"] = discord;
					j["gems"] = 0; // add things u wanna update in here!
					j["adminLevel"] = adminLevel;
					o << j << std::endl;
					o.close();

					cout << "Rebuilding at : " << dirEntry << endl;
				}
			}
			cout << "Rebuilt " << to_string(i) << " players." << endl;
		}
	}
}

void autoSaveWorlds() {
	while (1) {
		Sleep(3593000);
		string text = "action|play_sfx\nfile|audio/beep.wav\ndelayMS|0\n";
		BYTE* data = new BYTE[5 + text.length()];
		BYTE zero = 0;
		int type = 3;
		memcpy(data, &type, 4);
		memcpy(data + 4, text.c_str(), text.length());
		memcpy(data + 4 + text.length(), &zero, 1);
		ENetPacket * packet2 = enet_packet_create(data,
			5 + text.length(),
			ENET_PACKET_FLAG_RELIABLE);
		enet_host_broadcast(server, 0, packet2);
		GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`4Saving all worlds `oin `p5 `wseconds`o, you will be timed out for a short amount of time`w! `oDon't punch anything or you may get disconnected!``"));
		ENetPacket * packet = enet_packet_create(p.data,
			p.len,
			ENET_PACKET_FLAG_RELIABLE);
		enet_host_broadcast(server, 0, packet);
		delete data;
		delete p.data;
		Sleep(5500);
		saveAllWorlds();
	}
}

char* appendCharToCharArray(char* array, char a)
{
	size_t len = strlen(array);

	char* ret = new char[len + 2];

	strcpy(ret, array);
	ret[len] = a;
	ret[len + 1] = '\0';

	return ret;
}

int GetMacAddress(int a) {

}

int random_thing(float val) { return val / 2; }

#ifdef _WIN32
int _tmain(int argc, _TCHAR* argv[])
#else
int main()
#endif
{

	cout << "Growtopia private server (c) GTV3" << endl;
	cout << "Loading config from config.json" << endl;
	loadConfig();

	std::thread first(ServerInputPluginByplayingo);
	if (first.joinable()) {
		first.detach();
	}

	enet_initialize();



	//addAdmin("playingo", "why", 4);
	//addAdmin("ness", "why", 4);
	//addAdmin("esto", "why", 4);
	//addAdmin("finland", "why", 4);
	//addAdmin("rhinoceross", "why", 3);
	//addAdmin("iprogramincpp", "gr0w@why", 4);
	//addAdmin("nabsi", "why", 4);
	//addAdmin("karvapasi", "why", 3);
	//addAdmin("raiterjaki", "why", 3);
	//addAdmin("tough", "why", 1);
	//addAdmin("hashmumu", "why", 1);
	logs.open("serverlogs.txt", std::ios_base::app);

	std::ifstream t("totaluids.txt");
	std::string str((std::istreambuf_iterator<char>(t)),
		std::istreambuf_iterator<char>());
	totaluserids = atoi(str.c_str());

	thread autosaver(autoSaveWorlds);
	if (autosaver.joinable()) {
		autosaver.detach();
	}



	/*SQLHANDLE SQLEnvHandle = NULL;
	SQLHANDLE SQLConnectionHandle = NULL;
	SQLHANDLE SQLStatementHandle = NULL;
	SQLRETURN retCode = 0;
	char SQLQuery[] = "SELECT * FROM all";
	do {
		if (SQL_SUCCESS != SQLAllocHandle(SQL_HANDLE_ENV, SQL_NULL_HANDLE, &SQLEnvHandle))
			break;

		if (SQL_SUCCESS != SQLSetEnvAttr(SQLEnvHandle, SQL_ATTR_ODBC_VERSION, (SQLPOINTER)SQL_OV_ODBC3, 0))
			break;

		if (SQL_SUCCESS != SQLAllocHandle(SQL_HANDLE_DBC, SQLEnvHandle, &SQLConnectionHandle))
			break;

		if (SQL_SUCCESS != SQLSetConnectAttr(SQLConnectionHandle, SQL_LOGIN_TIMEOUT, (SQLPOINTER)5, 0))
			break;

		SQLCHAR retConString[1024];
		switch (SQLDriverConnect(SQLConnectionHandle, NULL, (SQLCHAR*)"DRIVER={SQL Server}; SERVER=remotemysql.com, 3306; DATABASE=UV1pzzVY0O; UID=UV1pzzVY0O; PWD=vXLd6UMrzX;", SQL_NTS, retConString, 1024, NULL,
			SQL_DRIVER_NOPROMPT)) {
		case SQL_SUCCESS:
			break;
		case SQL_SUCCESS_WITH_INFO:
			break;
		case SQL_NO_DATA_FOUND:
			showSQLError(SQL_HANDLE_DBC, SQLConnectionHandle);
			retCode = -1;
			break;
		case SQL_INVALID_HANDLE:
			showSQLError(SQL_HANDLE_DBC, SQLConnectionHandle);
			retCode = -1;
			break;
		case SQL_ERROR:
			showSQLError(SQL_HANDLE_DBC, SQLConnectionHandle);
			retCode = -1;
			break;
		default:
			break;
		}
		if (retCode == -1)
			break;

		if (SQL_SUCCESS != SQLAllocHandle(SQL_HANDLE_STMT, SQLConnectionHandle, &SQLStatementHandle))
			break;

		if (SQL_SUCCESS != SQLExecDirect(SQLStatementHandle, (SQLCHAR*)SQLQuery, SQL_NTS)) {
			showSQLError(SQL_HANDLE_STMT, SQLStatementHandle);
			break;
		}
		else {
			char username[256];

			while (SQLFetch(SQLStatementHandle) == SQL_SUCCESS) {
				SQLGetData(SQLStatementHandle, 1, SQL_C_DEFAULT, &username, sizeof(username), NULL);

				cout << username << " " << endl;
			}
		}

	} while (FALSE);

	SQLFreeHandle(SQL_HANDLE_STMT, SQLStatementHandle);
	SQLDisconnect(SQLConnectionHandle);
	SQLFreeHandle(SQL_HANDLE_DBC, SQLConnectionHandle);
	SQLFreeHandle(SQL_HANDLE_ENV, SQLEnvHandle);

	getchar();*/



	//ofstream off;
	//off.open("encrypteditemname.txt");
	/*char toencode[] = "Noobs";
	char encoded[sizeof(toencode) - 1];
	decodeName(toencode, sizeof(toencode) - 1, 2, encoded);

	cout << string_to_hex(encoded) << endl;
	off.close();*/

	//Unnecessary save at exit. Commented out to make the program exit slightly quicker.
	/*if (atexit(saveAllWorlds)) {
		cout << "Worlds won't be saved for this session..." << endl;
	}*/
	/*if (RegisterApplicationRestart(L" -restarted", 0) == S_OK)
	{
		cout << "Autorestart is ready" << endl;
	}
	else {
		cout << "Binding autorestart failed!" << endl;
	}
	Sleep(65000);
	int* p = NULL;
	*p = 5;*/
	signal(SIGINT, exitHandler);

	// load items.dat
	{
		std::ifstream file("items.dat", std::ios::binary | std::ios::ate);
		itemsDatSize = file.tellg();
		itemsDat = new BYTE[60 + itemsDatSize];
		string asdf = "0400000010000000FFFFFFFF000000000800000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
		for (int i = 0; i < asdf.length(); i += 2)
		{
			char x = ch2n(asdf[i]);
			x = x << 4;
			x += ch2n(asdf[i + 1]);
			memcpy(itemsDat + (i / 2), &x, 1);
			if (asdf.length() > 60 * 2) throw 0;
		}
		memcpy(itemsDat + 56, &itemsDatSize, 4);
		file.seekg(0, std::ios::beg);

		if (file.read((char*)(itemsDat + 60), itemsDatSize))
		{
			uint8_t* pData;
			int size = 0;
			const char filename[] = "items.dat";
			size = filesize(filename);
			pData = getA((string)filename, &size, false, false);
			cout << "Updating items data success! Hash: " << HashString((unsigned char*)pData, size) << endl;
			itemdathash = HashString((unsigned char*)pData, size);
			file.close();
			serializeItems();

		}
		else {
			cout << "Updating items data failed! (no items.dat file found!)" << endl;
		}
	}

	{
		std::ifstream files("normalitems.dat", std::ios::binary | std::ios::ate);
		itemsDatSizeNormal = files.tellg();
		itemsDatNormal = new BYTE[60 + itemsDatSizeNormal];
		string asdf2 = "0400000010000000FFFFFFFF000000000800000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
		for (int i = 0; i < asdf2.length(); i += 2)
		{
			char x = ch2n(asdf2[i]);
			x = x << 4;
			x += ch2n(asdf2[i + 1]);
			memcpy(itemsDatNormal + (i / 2), &x, 1);
			if (asdf2.length() > 60 * 2) throw 0;
		}
		memcpy(itemsDatNormal + 56, &itemsDatSizeNormal, 4);
		files.seekg(0, std::ios::beg);

		if (files.read((char*)(itemsDatNormal + 60), itemsDatSizeNormal))
		{
			uint8_t* pDatan;
			int size = 0;
			const char filename[] = "normalitems.dat";
			size = filesize(filename);
			pDatan = getA((string)filename, &size, false, false);
			cout << "Updating items data success! Hash: " << HashString((unsigned char*)pDatan, size) << endl;
			itemdathashNormal = HashString((unsigned char*)pDatan, size);
			files.close();


		}
		else {
			cout << "Updating items data failed! (no items.dat file found!)" << endl;
		}
	}


	cout << "Items.dat serialized! Loaded items: " << items.size() << endl;
	ofstream decompile;
	/*decompile.open("itemsdatdecompiled.txt", std::ios_base::app);
	for (int i = 0; i < items.size(); i++) {
		//cout << "Decompiling items.dat at id: " << items[i].id << " with name: " << items[i].name << endl;
		decompile << "name|" << items[i].name << endl;
		decompile << "audiofile|" << items[i].audiofile << endl;
		decompile << "id|" << items[i].id << endl;
		decompile << "editableType|" << items[i].editableType << endl;
		decompile << "itemCategory|" << items[i].category << endl;
		decompile << "actionType|" << items[i].type << endl;
		decompile << "solid|" << items[i].solid << endl;
		decompile << "color1|" << items[i].color1 << endl;
		decompile << "color2|" << items[i].color2 << endl;
		decompile << "textureX|" << items[i].textureX << endl;
		decompile << "textureY|" << items[i].textureY << endl;
		decompile << "textureType|" << items[i].textureType << endl;
		decompile << "hardness|" << items[i].hardness << endl;
		decompile << "audioVol|" << items[i].audioVol << endl;
		decompile << "texturehash|" << items[i].texturehash << endl;
		decompile << "audiohash|" << items[i].audiohash << endl;
		decompile << "seedBase|" << items[i].seedBase << endl;
		decompile << "seedOverlay|" << items[i].seedOverlay << endl;
		decompile << "treeBase|" << items[i].treeBase << endl;
		decompile << "treeOverlay|" << items[i].treeOverlay << endl;
		decompile << "\n";
	}
	decompile.close();*/

	//world = generateWorld();
	worldDB.get("TEST");
	worldDB.get("MAIN");
	worldDB.get("NEW");
	worldDB.get("ADMIN");
	ENetAddress address;
	/* Bind the server to the default localhost.     */
	/* A specific host address can be specified by   */
	enet_address_set_host(&address, "0.0.0.0");
	//address.host = ENET_HOST_ANY;
	/* Bind the server to port 1234. */
	address.port = configPort;
	server = enet_host_create(&address /* the address to bind the server host to */,
		512     /* allow up to 32 clients and/or outgoing connections */,
		10      /* allow up to 2 channels to be used, 0 and 1 */,
		0      /* assume any amount of incoming bandwidth */,
		0      /* assume any amount of outgoing bandwidth */);
	if (server == NULL)
	{
		fprintf(stderr,
			"An error occurred while trying to create an ENet server host.\n");
		while (1);
		exit(EXIT_FAILURE);
	}
	server->checksum = enet_crc32;
	enet_host_compress_with_range_coder(server);

	cout << "Building items database..." << endl;
	buildItemsDatabase();
	cout << "ItemDB SIZE: " << coredatasize << endl;
	cout << "Database is built!" << endl;
	enet_host_bandwidth_limit(server, 256000, 256000);



	thread queue(setupQueue);
	if (queue.joinable()) queue.detach();
	thread manage(manageGame);
	if (manage.joinable()) manage.detach();
	thread game(Game);
	if (game.joinable()) game.detach();



	ENetEvent event;
	/* Wait up to 1000 milliseconds for an event. */
	while (true) {
		if (serverIsFrozen == false) {
			while (enet_host_service(server, &event, 1000) > 0)
			{

				ENetPeer* peer = event.peer;
				if (!peer) continue;
				switch (event.type)
				{
				case ENET_EVENT_TYPE_CONNECT:
				{
#ifdef TOTAL_LOG
					printf("A new client connected.\n");
#endif


					ENetPeer * currentPeer;
					int count = 0;
					for (currentPeer = server->peers;
						currentPeer < &server->peers[server->peerCount];
						++currentPeer)
					{
						if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
							continue;
						if (currentPeer->address.host == peer->address.host)
							count++;
					}


					event.peer->data = new PlayerInfo;

					char clientConnection[16];
					enet_address_get_host_ip(&peer->address, clientConnection, 16);
					((PlayerInfo*)(peer->data))->charIP = clientConnection;
					((PlayerInfo*)(peer->data))->enetIP = peer->address.host;
					if (count > 3)
					{
						Player::OnConsoleMessage(peer, "`rToo many accounts are logged on from this IP.Log off one account before playing please.``");
						enet_peer_disconnect_later(peer, 0);
					}
					else {
						sendData(peer, 1, 0, 0);
					}
					lastIPLogon = peer->address.host;
					if (peer->address.host == lastIPLogon) {
						using namespace chrono;

						if (lastIPWait + 4000 < (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count())
						{
							lastIPWait = (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count();
						}
						else {
							Player::OnConsoleMessage(peer, "`o[ANTI-SPAM] Please wait 5 seconds before logging on again.``");
							enet_peer_disconnect_later(peer, 0);
						}
					}




					((PlayerInfo*)(peer->data))->lastSB = GetCurrentTimeInternal();
					/*memcpy(blockPtr, &worldInfo->blocks[i].foreground, 2);
					memcpy(blockPtr + 4, &type, 4);
					BYTE btype = 1;
					memcpy(blockPtr + 8, &btype, 1);

					string doorText = GetDoorText(worldInfo, i);
					const char* doorTextChars = doorText.c_str();
					short length = (short)doorText.size();
					memcpy(blockPtr + 9, &length, 2);
					memcpy(blockPtr + 11, doorTextChars, length);
					int minus1 = -1;
					memcpy(blockPtr + 11 + length, &minus1, 4);
					sizeofblockstruct += 4 + length;
					dataLen += 4 + length; // it's already 8.*/
					continue;
				}
				case ENET_EVENT_TYPE_RECEIVE:
				{
					
					if (serverIsFrozen) continue;
					if (event.packet->dataLength > 4096) {
						enet_peer_reset(peer);
						continue;
					}
					//cout << "PACKET DATA" << event.packet->data << endl;
					if ((char)event.packet->data == '\xFF') {
						Player::OnConsoleMessage(peer, "`oIf you see this contact the developer!");
						continue;
					}
					testCount(peer);

				
					
					if (((PlayerInfo*)(peer->data))->isIn == false) checkBan(peer);

					if (((PlayerInfo*)(peer->data))->isIn && ((PlayerInfo*)(peer->data))->rawName == "") enet_peer_disconnect_later(peer, 0);


					

					//if (((PlayerInfo*)(peer->data))->isUpdating)
					//{
						//cout << "packet drop" << endl;
						//continue;
					//}

					int messageType = GetMessageTypeFromPacket(event.packet);
					//cout << "Packet type is " << messageType << endl;
					//cout << (event->packet->data+4) << endl;
					WorldInfo* world = getPlyersWorld(peer);
					

					switch (messageType) {
					case 2:
					{
						string cch = GetTextPointerFromPacket(event.packet);
						cout << cch << endl;
						//cout << GetTextPointerFromPacket(event.packet) << endl;
						
						//logs.flush();
						string str = cch.substr(cch.find("text|") + 5, cch.length() - cch.find("text|") - 1);
						if (cch.find("action|wrench") == 0) {
							if (!world) continue;
							std::stringstream ss(cch);
							std::string to;
							int id = -1;
							while (std::getline(ss, to, '\n')) {
								vector<string> infoDat = explode("|", to);
								if (infoDat.size() < 3) continue;
								if (infoDat[1] == "netid") {
									string netid = infoDat[2].c_str();
									if (has_only_digits(netid) == false) continue;
									id = atoi(netid.c_str());
								}

							}
							if (id < 0) continue; //not found

							ENetPeer * currentPeer;
							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;

								if (isHere(peer, currentPeer)) {
									if (((PlayerInfo*)(currentPeer->data))->netID == id) {
										string name = ((PlayerInfo*)(currentPeer->data))->displayName;
										int lastuid = ((PlayerInfo*)(currentPeer->data))->userID;
										int gems = ((PlayerInfo*)(currentPeer->data))->gems;
										((PlayerInfo*)(peer->data))->lastTradeName = name;
										((PlayerInfo*)(peer->data))->lastUserID = lastuid;
										bool isHimSelf = false;
										bool isA = false;
										if (getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) > 2) isA = true;
										if (((PlayerInfo*)(currentPeer->data))->userID == ((PlayerInfo*)(peer->data))->userID) isHimSelf = true;
										sendWrench(peer, name, gems, isWorldOwner(peer, world), isA, isHimSelf);
										break;
									}

								}

							}
						}
						if (cch.find("action|respawn") == 0)
						{
							if (cch.find("action|respawn_spike") == 0) {
								playerRespawn(peer, true);
							}
							else
							{
								playerRespawn(peer, false);
							}
						}
						if (cch.find("action|trade_started") == 0) { // trading
							((PlayerInfo*)(peer->data))->currentTradeItems = "";
						}
						if (cch.find("action|trade_cancel") == 0) { // trading
							Player::OnForceTradeEnd(peer);
							((PlayerInfo*)(peer->data))->currentTradeItems = "";
						}
						if (cch.find("action|mod_trade") == 0) {
							// item id detection

							/*std::stringstream ss(cch);
							std::string to;
							int itemid = -1;
							while (std::getline(ss, to, '\n')) {
								vector<string> infoDat = explode("|", to);
								if (infoDat.size() == 2) {

									if (infoDat[0] == "itemID") itemid = atoi(infoDat[1].c_str());

								}
							}
							if (itemid == -1) continue;
							if (itemDefs.size() < itemid || itemid < 0) continue;

							((PlayerInfo*)(peer->data))->lastTradeItem = itemid;
							Player::OnDialogRequest(peer, "set_default_color|`o\n\nadd_label_with_icon|big|`w" + itemDefs.at(itemid).name + " <" + std::to_string(itemid) + ">``|left|" + std::to_string(itemid) + "|\n\nadd_textbox|How many to add`w?`o|left|\nadd_text_input|trditemcount|Amount: ||4|\nadd_spacer|small|\nadd_button|trdadditem|`2OK|0|0|\nadd_quick_exit|\nadd_spacer|big|\nend_dialog|popup|Nevermind|");*/
						}
						if (cch.find("action|trade_accept") == 0) { // trading

						}
						if (cch.find("action|growid") == 0)
						{
#ifndef REGISTRATION
							{
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "Registration is not supported yet!"));
								ENetPacket * packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
								delete p.data;
								//enet_host_flush(server);
							}
#endif
#ifdef REGISTRATION
							//GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`w" + itemDefs.at(id).name + "``|left|" + std::to_string(id) + "|\n\nadd_spacer|small|\nadd_textbox|" + itemDefs.at(id).description + "|left|\nadd_spacer|small|\nadd_quick_exit|\nadd_button|chc0|Close|noflags|0|0|\nnend_dialog|gazette||OK|"));
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`wGet a GrowID``|left|206|\n\nadd_spacer|small|\nadd_textbox|A `wGrowID `wmeans `oyou can use a name and password to logon from any device.|\nadd_spacer|small|\nadd_textbox|This `wname `owill be reserved for you and `wshown to other players`o, so choose carefully!|\nadd_text_input|username|GrowID||30|\nadd_text_input|password|Password||100|\nadd_text_input|passwordverify|Password Verify||100|\nadd_textbox|Your `wemail address `owill only be used for account verification purposes and won't be spammed or shared. If you use a fake email, you'll never be able to recover or change your password.|\nadd_text_input|email|Email||100|\nadd_textbox|Your `wDiscord ID `owill be used for secondary verification if you lost access to your `wemail address`o! Please enter in such format: `wdiscordname#tag`o. Your `wDiscord Tag `ocan be found in your `wDiscord account settings`o.|\nadd_text_input|discord|Discord||100|\nend_dialog|register|Cancel|Get My GrowID!|\n"));
							ENetPacket * packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;
#endif
						}
						if (cch.find("action|store") == 0)
						{
							sendShop(peer);
							//enet_host_flush(server);
						}
						if (cch.find("action|info") == 0)
						{
							std::stringstream ss(cch);
							std::string to;
							int id = -1;
							int count = -1;
							while (std::getline(ss, to, '\n')) {
								vector<string> infoDat = explode("|", to);
								if (infoDat.size() == 3) {
									if (infoDat[1] == "itemID") id = atoi(infoDat[2].c_str());
									if (infoDat[1] == "count") count = atoi(infoDat[2].c_str());
								}
							}
							if (id == -1 || count == -1) continue;
							if (itemDefs.size() < id || id < 0) continue;
							if (id > coredatasize - 2) continue;
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`w" + itemDefs.at(id).name + "``|left|" + std::to_string(id) + "|\n\nadd_spacer|small|\nadd_textbox|" + itemDefs.at(id).description + "|left|\nadd_spacer|small|\nadd_quick_exit|\nadd_button|chc0|Close|noflags|0|0|\nnend_dialog|gazette||OK|"));
							ENetPacket * packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);

							//enet_host_flush(server);
							delete p.data;
						}
						if (cch.find("action|dialog_return") == 0)
						{
							std::stringstream ss(cch);
							std::string to;
							string btn = "";
							bool isLockDialog = false;
							bool isRegisterDialog = false;
							bool isSignDialog = false;
							bool isTradeDialog = false;
							bool isStuffDialog = false;
							bool isOptionalStuffDialog = false;
							string pub = "";
							string disable_music = "";
							string tempo = "";
							string disable_music_render = "";
							string playerNetId = "";
							int receiveLevel = 0;
							string username = "";
							string password = "";
							string tradeitemcount = "";
							string stuffitem = "";
							string gravitystr = "";
							string passwordverify = "";
							string email = "";
							string discord = "";
							while (std::getline(ss, to, '\n')) {
								vector<string> infoDat = explode("|", to);
								if (infoDat.size() == 2) {

									//world->items[x + (y*world->width)].foreground
									if (infoDat[0] == "buttonClicked") btn = infoDat[1];
									if (infoDat[0] == "dialog_name" && infoDat[1] == "register")
									{
										isRegisterDialog = true;
									}
									if (infoDat[0] == "dialog_name" && infoDat[1] == "lock_edit") {
										isLockDialog = true;
									}
									if (infoDat[0] == "stuffitem")
									{
										isStuffDialog = true;

									}
									if (infoDat[0] == "dialog_name" && infoDat[1] == "signok")
									{
										isSignDialog = true;
									}
									if (infoDat[0] == "dialog_name" && infoDat[1] == "stuff")
									{
										isOptionalStuffDialog = true;
									}
									if (infoDat[0] == "dialog_name" && infoDat[1] == "popup")
									{

										isTradeDialog = true;
									}

									if (isOptionalStuffDialog) {
										/*int stuffgrav = -1;
										if (has_only_digits(infoDat[1])) {
											stuffgrav = atoi(infoDat[1].c_str());
										}
										if (stuffgrav > -1000 && stuffgrav < 1000) {
											int x = ((PlayerInfo*)(peer->data))->lastPunchX;
											int y = ((PlayerInfo*)(peer->data))->lastPunchY;
											updateStuffWeather(peer, ((PlayerInfo*)(peer->data))->lastPunchX, ((PlayerInfo*)(peer->data))->lastPunchY, world->items[x + (y*world->width)].displayBlock, stuffgrav, false, false);
										}*/
									}

									if (isRegisterDialog) {
										if (infoDat[0] == "username") username = infoDat[1];
										if (infoDat[0] == "password") password = infoDat[1];
										if (infoDat[0] == "passwordverify") passwordverify = infoDat[1];
										if (infoDat[0] == "email") email = infoDat[1];
										if (infoDat[0] == "discord") discord = infoDat[1];
									}
									if (isLockDialog) {
										if (infoDat[0] == "checkbox_public") pub = infoDat[1];
										if (infoDat[0] == "checkbox_disable_music") disable_music = infoDat[1];
										if (infoDat[0] == "tempo") tempo = infoDat[1];
										if (infoDat[0] == "checkbox_disable_music_render") disable_music_render = infoDat[1];
										if (infoDat[0] == "playerNetID") playerNetId = infoDat[1];
										if (world) {
											int x = ((PlayerInfo*)(peer->data))->lastPunchX;
											int y = ((PlayerInfo*)(peer->data))->lastPunchY;
											int fg = world->items[x + (y * world->width)].foreground;
											int bg = world->items[x + (y * world->width)].background;
											if (getItemDef(fg).blockType == BlockTypes::LOCK && has_only_digits(tempo) && has_only_digits(pub) && has_only_digits(disable_music) && has_only_digits(disable_music_render)) {

												if (playerNetId != "")
												{
													Player::OnConsoleMessage(peer, "`oThis feature (in this case: 'Accessing other players') is not supported!``");
													continue;
												}
												else {
													uint8_t lol = 0x00;
													int tempoint = atoi(tempo.c_str());
													if (disable_music_render == "1") {
														lol |= 0x20;
													}
													if (disable_music == "1") {

														lol |= 0x10;
													}
													ENetPeer* currentPeer;

													for (currentPeer = server->peers;
														currentPeer < &server->peers[server->peerCount];
														++currentPeer)
													{
														if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
															continue;
														if (isHere(peer, currentPeer)) {
															sendTileData(currentPeer, x, y, 0x00, fg, bg, lockTileDatas(lol, world->ownerId, 0, 0, false, tempoint));
														}
													}
													continue;

												}
											}
										}
									}
									if (isStuffDialog) {
										// VULNERABLE
										if (((PlayerInfo*)(peer->data))->currentWorld != "EXIT") {
											int stuffitemi = -1;
											int gravity = 100;

											int x = ((PlayerInfo*)(peer->data))->lastPunchX;
											int y = ((PlayerInfo*)(peer->data))->lastPunchY;

											if (infoDat[0] == "stuffitem") stuffitem = infoDat[1];
											if (infoDat[0] == "gravity") gravitystr = infoDat[1];
											if (has_only_digits(stuffitem)) stuffitemi = atoi(stuffitem.c_str());
											if (has_only_digits_wnegative(gravitystr)) gravity = atoi(gravitystr.c_str());

											if (gravity > -1000 && gravity < 1000 && stuffitemi > -1 && stuffitemi < 9142) {
												world->items[x + (y*world->width)].displayBlock = stuffitemi;
												world->items[x + (y*world->width)].gravity = gravity;
											}


											updateStuffWeather(peer, x, y, stuffitemi, world->items[x + (y * world->width)].background, gravity, false, false);
											getPlyersWorld(peer)->weather = 29;
										}

									}
									if (isSignDialog)
									{
										if (((PlayerInfo*)(peer->data))->currentWorld != "EXIT")
										{
											string signContent = infoDat[1];
											int x = ((PlayerInfo*)(peer->data))->lastPunchX;
											int y = ((PlayerInfo*)(peer->data))->lastPunchY;
											if (signContent.length() < 128) {
												world->items[x + (y*world->width)].sign = signContent;
												int fg = world->items[x + (y * world->width)].foreground;
												int bg = world->items[x + (y * world->width)].background;
												ENetPeer* currentPeer;

												for (currentPeer = server->peers;
													currentPeer < &server->peers[server->peerCount];
													++currentPeer)
												{
													if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
														continue;
													if (isHere(peer, currentPeer)) {
														updateSign(currentPeer, fg, bg, x, y, signContent);
													}
												}
											}
										}
									}
									if (isTradeDialog) {

										if (infoDat[0] == "trditemcount") tradeitemcount = infoDat[1];
									}
								}
							}
							if (btn == "estocape") {
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|\nadd_label_with_icon|big|`wAre you sure to buy `!Estonian Cape `wfor `52 `4DLS`w?``|left|9140|\nadd_spacer|small|\nadd_label|small|`2Sponsor your own custom item for 6 DLS and get 10 wls everytime someone buys it! If you want to buy, contact the GTV3 team and tell us your item idea and if you want us to release it, pay 6 DLS!|left|4|\nadd_button|yesesto|Yes!|0|0|\nadd_button|no|Back|0|0|\n\nadd_quick_exit|\nnend_dialog|gazette||OK|"));
								ENetPacket * packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
								delete p.data;
							}
							if (btn == "pull") {
								if (!world) continue;
								if (isWorldOwner(peer, world) || getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) > 1) {
									if (getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) > 1) {
										ENetPeer * currentPeer;
										for (currentPeer = server->peers;
											currentPeer < &server->peers[server->peerCount];
											++currentPeer)
										{
											if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
												continue;
											if (peer != currentPeer) {
												Player::OnSetPos(currentPeer, ((PlayerInfo*)(currentPeer->data))->netID, ((PlayerInfo*)(peer->data))->x, ((PlayerInfo*)(peer->data))->y);
												Player::PlayAudio(peer, "audio/object_spawn.wav", 150);
												Player::OnTextOverlay(currentPeer, "You were summoned by a mod.");
												break;
											}
										}
									}
									else {
										ENetPeer * currentPeer;
										for (currentPeer = server->peers;
											currentPeer < &server->peers[server->peerCount];
											++currentPeer)
										{
											if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
												continue;
											if (peer != currentPeer) {
												Player::OnSetPos(currentPeer, ((PlayerInfo*)(currentPeer->data))->netID, ((PlayerInfo*)(peer->data))->x, ((PlayerInfo*)(peer->data))->y);
												Player::PlayAudio(peer, "audio/object_spawn.wav", 150);
												Player::OnTextOverlay(currentPeer, "You were pulled by " + ((PlayerInfo*)(peer->data))->displayName);
												break;
											}
										}
									}
								}
							}
							if (btn == "punishview")
							{
								if (getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 4 || getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 3 || getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 5)
								{
									ENetPeer * currentPeerpx;

									for (currentPeerpx = server->peers;
										currentPeerpx < &server->peers[server->peerCount];
										++currentPeerpx)
									{
										if (currentPeerpx->state != ENET_PEER_STATE_CONNECTED)
											continue;

										if (((PlayerInfo*)(currentPeerpx->data))->userID == ((PlayerInfo*)(peer->data))->lastUserID) // if last wrench
										{
											sendPunishDialog(peer, ((PlayerInfo*)(currentPeerpx->data))->evadeRID, isAdminPeer(currentPeerpx), ((PlayerInfo*)(currentPeerpx->data))->displayName,
												((PlayerInfo*)(currentPeerpx->data))->charIP, ((PlayerInfo*)(currentPeerpx->data))->rid,
												((PlayerInfo*)(currentPeerpx->data))->sid, ((PlayerInfo*)(currentPeerpx->data))->mac);
										}
									}
								}
							}
							if (btn == "updateios") {

							}
							if (btn == "updateskip") {
								//Player::OnStartAcceptLogon(peer, itemdathash);
							}
							if (btn == "isbot") {
								((PlayerInfo*)(peer->data))->isBot = false;
							}
							if (btn == "yesesto") {
								Player::OnConsoleMessage(peer, "`oIf you want to buy dm GTV3 team!");
							}
							if (btn == "no") {
								sendShop(peer);
							}
							if (btn == "backtoexit") {
								if (((PlayerInfo*)(peer->data))->isInGame == true)
								{
									((PlayerInfo*)(peer->data))->isInGame = false;
									match.playersInGame--;
									sendPlayerLeave(peer, (PlayerInfo*)(event.peer->data));
									((PlayerInfo*)(peer->data))->currentWorld = "EXIT";
									sendWorldOffers(peer);
									Player::PlayAudio(peer, "audio/door_shut.wav", 0);
								}
							}
							if (btn == "worldPublic") if (((PlayerInfo*)(peer->data))->rawName == getPlyersWorld(peer)->owner) getPlyersWorld(peer)->isPublic = true;
							if (btn == "worldPrivate") if (((PlayerInfo*)(peer->data))->rawName == getPlyersWorld(peer)->owner) getPlyersWorld(peer)->isPublic = false;

							if (btn.substr(0, 4) == "tool") {
								if (has_only_digits(btn.substr(4, btn.length() - 4)) == false) break;
								int Id = atoi(btn.substr(4, btn.length() - 4).c_str());
								string ide = btn.substr(4, btn.length() - 4).c_str();
								size_t invsize = 250;

								if (((PlayerInfo*)(peer->data))->inventory.items.size() == invsize) {
									PlayerInventory inventory;
									InventoryItem item;
									item.itemID = Id;
									item.itemCount = 200;
									inventory.items.push_back(item);
									item.itemCount = 1;
									item.itemID = 18;
									inventory.items.push_back(item);
									item.itemID = 32;
									inventory.items.push_back(item);
									((PlayerInfo*)(peer->data))->inventory = inventory;

									sendConsoleMsg(peer, "`oItem `w" + ide + "`o has been `2added `oto your inventory.");

								}
								else {
									InventoryItem item;
									item.itemID = Id;
									item.itemCount = 200;
									((PlayerInfo*)(peer->data))->inventory.items.push_back(item);
									string ide = std::to_string(Id);
									sendConsoleMsg(peer, "`oItem `w" + ide + "`o has been `2added `oto your inventory.");


								}
								sendInventory(peer, ((PlayerInfo*)(peer->data))->inventory);
							}
							if (isTradeDialog) {
								((PlayerInfo*)(peer->data))->currentTradeItems += "add_slot|" + to_string(((PlayerInfo*)(peer->data))->lastTradeItem) + "|" + tradeitemcount + "locked|0reset_locks|1accepted|1\n"; // TODO TRADE
								Player::OnTradeStatus(peer, ((PlayerInfo*)(peer->data))->lastTradeNetID, ((PlayerInfo*)(peer->data))->lastTradeName, ((PlayerInfo*)(peer->data))->currentTradeItems);
							}
#ifdef REGISTRATION
							if (isRegisterDialog) {

								int regState = PlayerDB::playerRegister(peer, username, password, passwordverify, email, discord);
								if (regState == 1) {
									//((PlayerInfo*)(peer->data))->tankIDName = username;
									((PlayerInfo*)(peer->data))->tankIDName = username;
									((PlayerInfo*)(peer->data))->rawName = PlayerDB::getProperName(username);
									((PlayerInfo*)(peer->data))->displayName = username;
									((PlayerInfo*)(peer->data))->displayNamebackup = username;
									((PlayerInfo*)(peer->data))->socialName = username;
									((PlayerInfo*)(peer->data))->tankIDPass = password;
									ENetPeer * currentPeer;
									for (currentPeer = server->peers;
										currentPeer < &server->peers[server->peerCount];
										++currentPeer)
									{
										if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
											continue;
										if (isHere(peer, currentPeer))
										{
											Player::OnNameChanged(currentPeer, ((PlayerInfo*)(peer->data))->netID, username);
										}
									}
									Player::SetHasGrowID(peer, 1, username, password);
									Player::PlayAudio(peer, "audio/spell1.wav", 150);
									GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|GrowID GET!``|left|18|\nadd_label|small|``A `wGrowID ``with the log on of `w" + username + " ``and the password of `w" + password + " ``created. Write them down, they will be required to log on from now on!|left|4|\nadd_button|cntn|Continue.|NOFLAGS||0|0|\nend_dialog|regsuccess|||\n"));
									ENetPacket * packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(peer, 0, packet);
									delete p.data;
									((PlayerInfo*)(peer->data))->haveGrowId = true;
								}
								else if (regState == -1) {
									GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`rAccount creation has failed, because it already exists!``"));
									ENetPacket * packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(peer, 0, packet);
									delete p.data;
								}
								else if (regState == -2) {
									GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`rAccount creation has failed, because the password or name is too short!``"));
									ENetPacket * packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(peer, 0, packet);
									delete p.data;
								}
								else if (regState == -3) {
									GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`4Passwords mismatch!``"));
									ENetPacket * packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(peer, 0, packet);
									delete p.data;
								}
								else if (regState == -4) {
									GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`4Account creation has failed, because email address is invalid!``"));
									ENetPacket * packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(peer, 0, packet);
									delete p.data;
								}
								else if (regState == -5) {
									GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`4Account creation has failed, because Discord ID is invalid!``"));
									ENetPacket * packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(peer, 0, packet);
									delete p.data;
								}
							}
#endif
						}
						string dropText = "action|drop\n|itemID|";
						if (cch.find(dropText) == 0)
						{
							if (!world) continue;
							string itemd = cch.substr(dropText.length(), cch.length() - dropText.length() - 1);
							if (has_only_digits(itemd)) {
								int item = atoi(itemd.c_str());
								if (item != 18 && item != 32) {
									dropItem(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -1 : 1)), ((PlayerInfo*)(peer->data))->y, item, 1, 0, world);
								}
								else {
									Player::OnTextOverlay(peer, "You cannot lose that!");
								}
							}
							/*int itemID = atoi(cch.substr(dropText.length(), cch.length() - dropText.length() - 1).c_str());
							PlayerMoving data;
							data.packetType = 14;
							data.x = ((PlayerInfo*)(peer->data))->x;
							data.y = ((PlayerInfo*)(peer->data))->y;
							data.netID = -1;
							data.plantingTree = itemID;
							float val = 1; // item count
							BYTE val2 = 0; // if 8, then geiger effect

							BYTE* raw = packPlayerMoving(&data);
							memcpy(raw + 16, &val, 4);
							memcpy(raw + 1, &val2, 1);
							SendPacketRaw(4, raw, 56, 0, peer, ENET_PACKET_FLAG_RELIABLE);*/
						}
						if (cch.find("text|") != std::string::npos) {

							PlayerInfo* pData = ((PlayerInfo*)(peer->data));
							if (pData->currentWorld == "EXIT") continue;

							if (str.length() > 256) continue;
							/*std::transform(str.begin(), str.end(), str.begin(),
								[](unsigned char c) { return tolower(c); });*/
								//Player::OnConsoleMessage(peer, "`o" + str + "``");
							bool isActioned = false;
							if (str.length() && str[0] == '/')
							{
								Player::OnConsoleMessage(peer, "`6" + str + "``");
								sendAction(peer, ((PlayerInfo*)(peer->data))->netID, str);
								isActioned = true;
							}
							if (str == "/mod")
							{
								//((PlayerInfo*)(peer->data))->canWalkInBlocks = true;
								//sendState(peer);
								/*PlayerMoving data;
								data.packetType = 0x14;
								data.characterState = 0x0; // animation
								data.x = 1000;
								data.y = 1;
								data.punchX = 0;
								data.punchY = 0;
								data.XSpeed = 300;
								data.YSpeed = 600;
								data.netID = ((PlayerInfo*)(peer->data))->netID;
								data.plantingTree = 0xFF;
								SendPacketRaw(4, packPlayerMoving(&data), 56, 0, peer, ENET_PACKET_FLAG_RELIABLE);*/
							}
							else if (str.substr(0, 6) == "/ghost") {

								ENetPeer* currentPeer;
								int netid = ((PlayerInfo*)(peer->data))->netID;
								if (((PlayerInfo*)(peer->data))->canWalkInBlocks == false) {
									((PlayerInfo*)(peer->data))->canWalkInBlocks = true;
									((PlayerInfo*)(peer->data))->skinColor = -251658400;
									sendState(peer, ((PlayerInfo*)(peer->data)));
									for (currentPeer = server->peers;
										currentPeer < &server->peers[server->peerCount];
										++currentPeer)
									{
										if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
											continue;
										Player::OnChangeSkin(currentPeer, -160, netid); // -137
									}
									Player::OnConsoleMessage(peer, "`oYour atoms are suddenly aware of quantum tunneling. (`$Ghost in the Shell `omod added)``");
								}
								else {
									((PlayerInfo*)(peer->data))->canWalkInBlocks = false;
									((PlayerInfo*)(peer->data))->skinColor = 0x8295C3FF;
									sendState(peer, ((PlayerInfo*)(peer->data)));
									Player::PlayAudio(peer, "audio/dialog_confirm.wav", 0);
									for (currentPeer = server->peers;
										currentPeer < &server->peers[server->peerCount];
										++currentPeer)
									{
										if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
											continue;
										Player::OnChangeSkin(currentPeer, 0x8295C3FF, netid);
									}

									Player::OnConsoleMessage(peer, "`oYour body stops shimmering and returns to normal. (`$Ghost in the Shell `omod removed)``");
								}
							}

							else if (str.substr(0, 7) == "/state ")
							{
								/*PlayerMoving data;
								data.packetType = 0x14;
								data.characterState = 0x0; // animation
								data.x = 1000;
								data.y = 0;
								data.punchX = 0;
								data.punchY = 0;
								data.XSpeed = 300;
								data.YSpeed = 600;
								data.netID = ((PlayerInfo*)(peer->data))->netID;
								data.plantingTree = atoi(str.substr(7, cch.length() - 7 - 1).c_str());
								SendPacketRaw(4, packPlayerMoving(&data), 56, 0, peer, ENET_PACKET_FLAG_RELIABLE);*/
							}
							else if (str == "/unequip")
							{
								((PlayerInfo*)(peer->data))->cloth_hair = 0;
								((PlayerInfo*)(peer->data))->cloth_shirt = 0;
								((PlayerInfo*)(peer->data))->cloth_pants = 0;
								((PlayerInfo*)(peer->data))->cloth_feet = 0;
								((PlayerInfo*)(peer->data))->cloth_face = 0;
								((PlayerInfo*)(peer->data))->cloth_hand = 0;
								((PlayerInfo*)(peer->data))->cloth_back = 0;
								((PlayerInfo*)(peer->data))->cloth_mask = 0;
								((PlayerInfo*)(peer->data))->cloth_necklace = 0;
								((PlayerInfo*)(peer->data))->cloth_ances = 0;
								sendClothes(peer);
							}

							else if (str.substr(0, 6) == "/find ")
							{


								string itemFind = str.substr(6, cch.length() - 6 - 1);
								if (itemFind.length() < 3) {
									Player::OnConsoleMessage(peer, "`4Find items more than `63 `2characters `wplease`o!``");
									Player::OnTalkBubble(peer, ((PlayerInfo*)(peer->data))->netID, "`4Find items more than `63 `2characters `wplease`o!``", 0, false);
									break;
								}
							SKIPFind:;

								string itemLower2;
								vector<ItemDefinition> itemDefsfind;
								for (char c : itemFind) if (c < 0x20 || c>0x7A) goto SKIPFind;
								if (itemFind.length() < 3) goto SKIPFind3;
								for (const ItemDefinition& item : itemDefs)
								{
									string itemLower;
									for (char c : item.name) if (c < 0x20 || c>0x7A) goto SKIPFind2;
									if (!(item.id % 2 == 0)) goto SKIPFind2;
									itemLower2 = item.name;
									std::transform(itemLower2.begin(), itemLower2.end(), itemLower2.begin(), ::tolower);
									if (itemLower2.find(itemLower) != std::string::npos) {
										itemDefsfind.push_back(item);
									}
								SKIPFind2:;
								}
							SKIPFind3:;
								string listMiddle = "";
								string listFull = "";


								for (const ItemDefinition& item : itemDefsfind)
								{
									if (item.name != "") {
										string kys = item.name;
										std::transform(kys.begin(), kys.end(), kys.begin(), ::tolower);
										string kms = itemFind;
										std::transform(kms.begin(), kms.end(), kms.begin(), ::tolower);
										if (kys.find(kms) != std::string::npos)
											listMiddle += "add_button_with_icon|tool" + to_string(item.id) + "|`$" + item.name + "``|left|" + to_string(item.id) + "||\n";

									}
								}
								if (itemFind.length() < 3) {
									listFull = "add_textbox|`4Word is less then 3 letters!``|\nadd_spacer|small|\n";
									Player::showWrong(peer, listFull, itemFind);
								}
								else if (itemDefsfind.size() == 0) {
									//listFull = "add_textbox|`4Found no item match!``|\nadd_spacer|small|\n";
									Player::showWrong(peer, listFull, itemFind);

								}
								else {
									if (listMiddle.size() == 0) {
										Player::OnConsoleMessage(peer, "`wNo `3items found`o.");
									}
									else
									{

										GamePacket fff = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "add_label_with_icon|big|`wFound item : " + itemFind + "``|left|6016|\nadd_spacer|small|\nend_dialog|findid|Cancel|\nadd_spacer|big|\n" + listMiddle + "add_quick_exit|\n"));
										ENetPacket* packetd = enet_packet_create(fff.data,
											fff.len,
											ENET_PACKET_FLAG_RELIABLE);
										enet_peer_send(peer, 0, packetd);

										//enet_host_flush(server);
										delete fff.data;
									}
								}

							}

							else if (str == "/cleaninv") {
								PlayerInventory inventory;
								InventoryItem item;
								inventory.items.clear();
								item.itemCount = 1;
								item.itemID = 18;
								inventory.items.push_back(item);
								item.itemID = 32;
								inventory.items.push_back(item);
								((PlayerInfo*)(peer->data))->inventory = inventory;
								sendInventory(peer, inventory);
							}
							else if (str == "/mods") {
								string x;
								int mods = 0;
								ENetPeer* currentPeer;

								for (currentPeer = server->peers;
									currentPeer < &server->peers[server->peerCount];
									++currentPeer)
								{
									if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
										continue;
									if (((PlayerInfo*)(currentPeer->data))->isNicked == false) {
										if (getAdminLevel(((PlayerInfo*)(currentPeer->data))->rawName, ((PlayerInfo*)(currentPeer->data))->tankIDPass) == 3) {
											x.append(((PlayerInfo*)(currentPeer->data))->displayName + "``, ");
										}
										else if (getAdminLevel(((PlayerInfo*)(currentPeer->data))->rawName, ((PlayerInfo*)(currentPeer->data))->tankIDPass) > 3) {
											x.append(((PlayerInfo*)(currentPeer->data))->displayName + "``, ");
										}
										mods++;
									}

								}
								x = x.substr(0, x.length() - 2);
								if (mods > 0) {
									Player::OnConsoleMessage(peer, "``Moderators online: " + x);
								}
								else {
									Player::OnConsoleMessage(peer, "``Moderators online: (None visible)");
								}
							}
							else if (str.substr(0, 6) == "/tape ") {
								if (getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) > 1) {
									string name = str.substr(6, str.length());

									ENetPeer* currentPeer;

									bool found = false;

									for (currentPeer = server->peers;
										currentPeer < &server->peers[server->peerCount];
										++currentPeer)
									{
										if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
											continue;

										if (((PlayerInfo*)(currentPeer->data))->rawName == name) {
											found = true;
											if (((PlayerInfo*)(currentPeer->data))->taped) {
												((PlayerInfo*)(currentPeer->data))->taped = false;
												GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`2You are no longer duct-taped!"));
												ENetPacket * packet = enet_packet_create(p.data,
													p.len,
													ENET_PACKET_FLAG_RELIABLE);
												enet_peer_send(currentPeer, 0, packet);
												delete p.data;
												{
													Player::OnConsoleMessage(peer, "`oRemoved `bduct-tape `ofrom `w" + name);
												}
											}
											else {
												((PlayerInfo*)(currentPeer->data))->taped = true;
												GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`4You have been duct-taped!"));
												ENetPacket * packet = enet_packet_create(p.data,
													p.len,
													ENET_PACKET_FLAG_RELIABLE);
												enet_peer_send(currentPeer, 0, packet);
												{
													Player::OnConsoleMessage(peer, "`oUsed `bduct-tape `oon `w" + name);
												}
											}
										}
									}
									if (!found) {
										Player::OnConsoleMessage(peer, "`4ERROR! `w" + name + " `owasn't found. Syntax: `w/tape (player)``");
									}
								}
								else {
									Player::OnConsoleMessage(peer, "`4ERROR! `oUnknown command, use `w/help `oto get a list of working commands.``");
								}
							}
							else if (str == "/save") {

							}
							else if (str.substr(0, 6) == "/warp ") {
							
								if (getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) > 0) {
									string name = str.substr(6, str.length());
									name = getStrUpper(name);
									if (name.length() > 0) {
										if (name != "EXIT") {
											Player::OnConsoleMessage(peer, "`oMagically warping to `w" + name + "`o.``");
											if (configPort == 17093) {
												Player::OnConsoleMessage(peer, "`w" + name + " `onot located in same server, sending!``");
												
																								
												continue;
											}
											//joinWorld(peer, name);
											
										}
										else {
											Player::OnConsoleMessage(peer, "`4You cant enter the `wworld selection menu`o!``");
										}
									}
									else {
										Player::OnConsoleMessage(peer, "`4World cannot be `wnothing`o!``");
									}
								}
							}

							else if (str.substr(0, 6) == "/pull ") {
								if (!world) continue;
								if (getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) > 1) {
									string name = str.substr(6, str.length());
									std::transform(name.begin(), name.end(), name.begin(), ::tolower);
									ENetPeer* currentPeer;
									bool found = false;
									for (currentPeer = server->peers;
										currentPeer < &server->peers[server->peerCount];
										++currentPeer)
									{
										if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
											continue;

										string name2 = ((PlayerInfo*)(currentPeer->data))->rawName;

										if (name == name2 && getAdminLevel(((PlayerInfo*)(currentPeer->data))->rawName, ((PlayerInfo*)(currentPeer->data))->tankIDPass) < 2) {
											if (((PlayerInfo*)(currentPeer->data))->isIn) {
												if (isHere(peer, currentPeer)) {
													if (peer == currentPeer) continue;
													found = true;
													Player::OnSetPos(currentPeer, ((PlayerInfo*)(currentPeer->data))->netID, ((PlayerInfo*)(peer->data))->x, ((PlayerInfo*)(peer->data))->y);
													Player::PlayAudio(peer, "audio/object_spawn.wav", 150);
													Player::OnTextOverlay(currentPeer, "You were summoned by a mod.");
													break;
												}
												else {
													Player::OnTextOverlay(currentPeer, "You were summoned by a mod.");
													sendPlayerToPlayer(currentPeer, peer);
													found = true;
													break;
												}
											}
										}
										else {

										}
									}
									if (found) {
										Player::OnConsoleMessage(peer, "`oSummoning `w" + name + " (`oCross-side server pulling not implemented yet.`w)``");
									}
									else {
										Player::OnConsoleMessage(peer, "`4Player not found!``");
									}
								}
								else {
									if (isWorldOwner(peer, world)) {
										string name = str.substr(6, str.length());
										std::transform(name.begin(), name.end(), name.begin(), ::tolower);
										ENetPeer* currentPeer;
										bool found = false;
										for (currentPeer = server->peers;
											currentPeer < &server->peers[server->peerCount];
											++currentPeer)
										{
											if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
												continue;

											string name2 = ((PlayerInfo*)(currentPeer->data))->rawName;

											if (name == name2 && getAdminLevel(((PlayerInfo*)(currentPeer->data))->rawName, ((PlayerInfo*)(currentPeer->data))->tankIDPass) < 2) {
												if (((PlayerInfo*)(currentPeer->data))->isIn) {
													if (isHere(peer, currentPeer)) {
														if (peer == currentPeer) continue;
														Player::OnSetPos(currentPeer, ((PlayerInfo*)(currentPeer->data))->netID, ((PlayerInfo*)(peer->data))->x, ((PlayerInfo*)(peer->data))->y);
														Player::PlayAudio(peer, "audio/object_spawn.wav", 150);
														Player::OnTextOverlay(currentPeer, "You were pulled by " + ((PlayerInfo*)(peer->data))->displayName);
														break;
													}
												}
											}
											else {
												Player::OnTextOverlay(peer, "Cannot pull this player!");
											}
										}
									}
								}
							}
							else if (str == "/magic") {
								if (getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) > 0) {
									if (!world) continue;
									float x = ((PlayerInfo*)(peer->data))->x;
									float y = ((PlayerInfo*)(peer->data))->y;
									ENetPeer* currentPeer;
									for (currentPeer = server->peers;
										currentPeer < &server->peers[server->peerCount];
										++currentPeer)
									{
										if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
											continue;
										Player::OnParticleEffect(currentPeer, 90, x, y, 0);
									}

									bool found = false;
									for (currentPeer = server->peers;
										currentPeer < &server->peers[server->peerCount];
										++currentPeer)
									{
										if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
											continue;
										if (isHere(peer, currentPeer)) {
											bool isRev = false;
											for (int i = 5; i < 45; i++) {
												if (isRev == false) {
													Player::OnParticleEffect(currentPeer, 3, x + i * (rand() % 9), y + i * (rand() % 9), i * 100);
													Player::OnParticleEffect(currentPeer, 2, x + i * (rand() % 9), y + i * (rand() % 9), i * 100);
													isRev = true;
												}
												else {
													Player::OnParticleEffect(currentPeer, 3, x - i * (rand() % 9), y - i * (rand() % 9), i * 100);
													Player::OnParticleEffect(currentPeer, 2, x + i * (rand() % 9), y + i * (rand() % 9), i * 100);
													isRev = false;
												}
											}
										}
									}
								}
							}
							else if (str.substr(0, 10) == "/particle ") {
								string p = str.substr(10, str.length());
								if (p.length() > 0 && has_only_digits(p)) Player::OnParticleEffect(peer, atoi(p.c_str()), ((PlayerInfo*)(peer->data))->x, ((PlayerInfo*)(peer->data))->y, 0);
							}
							else if (str.substr(0, 8) == "/warpto ") {
								if (getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) > 2) {
									string name = str.substr(8, str.length());

									ENetPeer* currentPeer;
									bool found = false;
									for (currentPeer = server->peers;
										currentPeer < &server->peers[server->peerCount];
										++currentPeer)
									{
										if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
											continue;

										string name2 = ((PlayerInfo*)(currentPeer->data))->rawName;
										std::transform(name.begin(), name.end(), name.begin(), ::tolower);
										std::transform(name2.begin(), name2.end(), name2.begin(), ::tolower);

										if (name == name2) {
											if (((PlayerInfo*)(currentPeer->data))->currentWorld == "EXIT" || getAdminLevel(((PlayerInfo*)(currentPeer->data))->rawName, ((PlayerInfo*)(currentPeer->data))->tankIDPass) > 3)
											{
												Player::OnConsoleMessage(peer, "`9Player not found.``");
											}
											else
											{
												sendPlayerToPlayer(peer, currentPeer);
												found = true;
											}

										}
									}
									if (found) {
										Player::OnConsoleMessage(peer, "`o[INFO : PLAYER IS IN SAME SERVER] `9Magically warping to player " + name + "`w...``");
									}
									else {
										Player::OnConsoleMessage(peer, "`4Player not found or is currently in EXIT.``");
									}
								}
							}
							else if (str == "/getgift") {

							}
							else if (str == "/whatsnetid") {
								//Player::OnTalkBubble(peer, ((PlayerInfo*)(peer->data))->netID, "`pnetID is: " + to_string(((PlayerInfo*)(peer->data))->netID) + "``", 0, true);
							}
							else if (str == "/testban") {
								//world->banned.push_back("lol|time");
								//cout << world->banned[0] << endl;
							}

							else if (str == "/clearworld") {
								if (getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 4) {
									int x = 0;
									int y = 0;
									if (((PlayerInfo*)(peer->data))->currentWorld != "EXIT") {
										TileExtra data;
										data.packetType = 0x5;
										data.characterState = 8;
										data.charStat = 8;
										data.blockid = 0;
										data.backgroundid = 0;
										data.visual = 0x00010000;

										for (int i = 0; i < world->width * world->height; i++)
										{
											if (world->items[i].foreground != 6 && world->items[i].foreground != 8 && getItemDef(world->items[i].foreground).blockType != BlockTypes::LOCK) {


												world->items[i].foreground = 0;
												world->items[i].background = 0;
												x = (i % world->width);
												y = (i / world->width);
												data.punchX = x;
												data.punchY = y;
												ENetPeer * currentPeer;
												for (currentPeer = server->peers;
													currentPeer < &server->peers[server->peerCount];
													++currentPeer)
												{
													if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
														continue;
													if (isHere(peer, currentPeer))
													{
														SendPacketRaw2(192, packBlockVisual(&data), 100, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
													}
												}
											}
										}

										Player::OnConsoleMessage(peer, "`oUsed `4GTV3's `2Fast-Realtime-Clear system`w (like real gt)!``");
									}
								}
							}

							else if (str == "/clearlocks") {
								if (getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 4) {
									int x = 0;
									int y = 0;
									if (((PlayerInfo*)(peer->data))->currentWorld != "EXIT") {
										TileExtra data;
										data.packetType = 0x5;
										data.characterState = 8;
										data.charStat = 8;
										data.blockid = 0;
										data.backgroundid = 0;
										data.visual = 0x00010000;

										for (int i = 0; i < world->width * world->height; i++)
										{
											if (world->items[i].foreground != 6 && world->items[i].foreground != 8) {


												world->items[i].foreground = 0;
												world->items[i].background = 0;
												x = (i % world->width);
												y = (i / world->width);
												data.punchX = x;
												data.punchY = y;
												ENetPeer * currentPeer;
												for (currentPeer = server->peers;
													currentPeer < &server->peers[server->peerCount];
													++currentPeer)
												{
													if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
														continue;
													if (isHere(peer, currentPeer))
													{
														SendPacketRaw2(192, packBlockVisual(&data), 100, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
													}
												}
											}
										}

										Player::OnConsoleMessage(peer, "`oUsed `4GTV3's `2Fast-Realtime-Clear system`w (like real gt)!``");
									}
								}
							}

							//if (world->items[i].foreground != 0 && world->items[i].foreground != 6 && world->items[i].foreground != 8 && getItemDef(world->items[i].foreground).blockType != BlockTypes::LOCK) {

							else if (str == "/news") {
								sendGazette(peer);
							}


							else if (str == "/testsound") {
								//Player::PlayAudio(peer, "audio/ogg/gtv3_survive_ends.ogg", 870000);

							}
							else if (str == "/online") {
								int players = 0;
								ENetPeer * currentPeer;
								for (currentPeer = server->peers;
									currentPeer < &server->peers[server->peerCount];
									++currentPeer)
								{
									if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
										continue;
									players = players + 1;
								}
								Player::OnTalkBubble(peer, ((PlayerInfo*)(peer->data))->netID, "Players online: " + to_string(players) + ".", 6, true);
							}
							else if (str == "/testdelay") {
								//Player::OnSetFreezeState(peer, 2, ((PlayerInfo*)(peer->data))->netID);
							}
							else if (str == "/testsound2") {
								//Player::OnCountdownStart(peer, -1, 90, 200);
							}
							else if (str == "/testflag") {
								Player::OnFlagMay2019(peer, 1, ((PlayerInfo*)(peer->data))->netID);
							}
							else if (str == "/testbillboard") {
								ENetPeer * currentPeer;
								for (currentPeer = server->peers;
									currentPeer < &server->peers[server->peerCount];
									++currentPeer)
								{
									if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
										continue;
									if (isHere(peer, currentPeer))
									{
										Player::OnBillboardChange(currentPeer, ((PlayerInfo*)(peer->data))->netID);
									}
								}
							}
							else if (str == "/paid") {
								string paiddone;

								string paidlist;

								for (std::vector<string>::const_iterator i = ((PlayerInfo*)(peer->data))->paid.begin(); i != ((PlayerInfo*)(peer->data))->paid.end(); ++i) {
									paiddone = *i;
									paidlist += paiddone + " ";
								}

								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "Transactions made this login: " + paidlist));
								ENetPacket * packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
								delete p.data;
							}
							else if (str.substr(0, 5) == "/pay ") {
								if (((PlayerInfo*)(peer->data))->haveGrowId) {
									bool valid = true;
									string x = str.substr(5, cch.length() - 5 - 1);

									int pos = x.find(" ");
									string gemcount = x.substr(pos + 1);

									std::string addrWithMask(x);
									std::size_t pos1 = addrWithMask.find(" ");
									std::string playername = addrWithMask.substr(0, pos1);

									cout << "/pay from " + ((PlayerInfo*)(peer->data))->rawName << " to: " + playername + " " + gemcount << endl;

									bool contains_non_alpha
										= !std::regex_match(gemcount, std::regex("^[0-9]+$"));

									for (char c : playername)
									{
										if (std::all_of(playername.begin(), playername.end(), isspace))
										{
											valid = false;
										}
									}

									if (contains_non_alpha || playername == "" || valid == false)
									{

										Player::OnConsoleMessage(peer, "`oInvalid syntax. Usage: /pay <name> <amount>``");
										break;

									}

									int gems = ((PlayerInfo*)(peer->data))->gems;
									if (atoi(gemcount.c_str()) > gems)
									{
										Player::OnConsoleMessage(peer, "`oNot enough `4gems`o.``");
										continue;
									}

									// peer variables
									bool found = false;
									// TODO GEM SYSTEM!!!
									int sgA1 = gems;
									int sgR1 = atoi(gemcount.c_str());
									int gemcalcminus = sgA1 - sgR1;
									// peer variables
									string pname = ((PlayerInfo*)(peer->data))->rawName;
									ENetPeer * currentPeer;
									for (currentPeer = server->peers;
										currentPeer < &server->peers[server->peerCount];
										++currentPeer)
									{
										if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
											continue;

										if (isHere(peer, currentPeer))
										{
											if (((PlayerInfo*)(currentPeer->data))->haveGrowId == false) {
												Player::OnConsoleMessage(peer, "`wPlayer does not have a GrowID!``");
												break;
											}
											if (PlayerDB::getProperName(playername) == ((PlayerInfo*)(currentPeer->data))->rawName) {
												string chkname = ((PlayerInfo*)(currentPeer->data))->rawName;

												if (chkname == PlayerDB::getProperName(((PlayerInfo*)(peer->data))->rawName))
												{
													break;
												}

												if (atoi(gemcount.c_str()) < 50)
												{
													found = true;
													Player::OnConsoleMessage(peer, "`oMaximum gem amount is 1000000$`o.``");
													break;
												}

												if (atoi(gemcount.c_str()) > 1000000)
												{
													found = true;
													Player::OnConsoleMessage(peer, "`oMaximum gem amount is 1000000$`o.``");
													break;

												}

												found = true;
												((PlayerInfo*)(peer->data))->gems = gemcalcminus;

												int sgA2 = ((PlayerInfo*)(currentPeer->data))->gems;
												int sgR2 = atoi(gemcount.c_str());
												int gemcalcplus = sgA2 + sgR2;
												((PlayerInfo*)(currentPeer->data))->gems = gemcalcplus;

												Player::OnSetBux(peer, gemcalcminus, 0);
												Player::OnSetBux(currentPeer, gemcalcplus, 0);
												time_t now = time(0);
												const char* dt = ctime(&now);
												tm* gmtm = gmtime(&now);
												dt = asctime(gmtm);
												std::string sendtime(dt);
												if (gmtm != NULL) {
												}
												else {
													break;
												}
												Player::OnConsoleMessage(peer, "`oSent " + gemcount + " to " + ((PlayerInfo*)(currentPeer->data))->displayName + ".``");
												((PlayerInfo*)(peer->data))->paid.push_back("[UTC] (" + sendtime + "): `oSent " + gemcount + " to " + ((PlayerInfo*)(currentPeer->data))->displayName + ".``");
												((PlayerInfo*)(currentPeer->data))->paid.push_back("[UTC] (" + sendtime + "): `oReceived " + gemcount + " from " + ((PlayerInfo*)(peer->data))->displayName + ".``");
												Player::OnConsoleMessage(currentPeer, "`oReceived " + gemcount + " from " + ((PlayerInfo*)(peer->data))->displayName + ".``");
												bool existx = std::experimental::filesystem::exists("players/_" + pname + ".json");
												if (existx == false) {
													continue;
												}
											}
										}
									}
									if (found == false)
									{
										Player::OnConsoleMessage(peer, "`oPlayer was not found in this world.``");
									}
								}

							}


							else if (str == "/help") {
								sendHelp(peer, getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass));
							}
							else if (str == "/boot") {
								if (world) {
									Player::OnConsoleMessage(peer, "`oAttempting to disconnect every player in this world`w...");
									ENetPeer* currentPeer;
									for (currentPeer = server->peers;
										currentPeer < &server->peers[server->peerCount];
										++currentPeer)
									{
										if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
											continue;
										if (isHere(peer, currentPeer))
										{
											if (peer != currentPeer) {
												enet_peer_disconnect_later(currentPeer, 0);
											}
										}
									}
								}
							}
							else if (str == "/invis" || str == "/invisible") {
								if (getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) > 1) {
									int peernetid = ((PlayerInfo*)(peer->data))->netID;
									PlayerInfo* pData = ((PlayerInfo*)(peer->data));
									//sendConsoleMsg(peer, "`6" + str);
									if (pData->isinv == false) {

										pData->isinv = true;
										Player::OnConsoleMessage(peer, "`oYou are now ninja, invisible to all.");
										Player::OnInvis(peer, 1, peernetid);
										((PlayerInfo*)(peer->data))->isinv = 1;
										ENetPeer* currentPeer;

										for (currentPeer = server->peers;
											currentPeer < &server->peers[server->peerCount];
											++currentPeer)
										{
											if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
												continue;
											if (isHere(peer, currentPeer))
											{
												Player::OnInvis(currentPeer, 1, peernetid);
											}
										}

									}
									else {
										Player::OnConsoleMessage(peer, "`oYou are once again visible to mortals.");
										Player::OnInvis(peer, 0, peernetid);
										pData->isinv = false;
										ENetPeer * currentPeer;
										for (currentPeer = server->peers;
											currentPeer < &server->peers[server->peerCount];
											++currentPeer)
										{
											if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
												continue;
											if (isHere(peer, currentPeer))
											{
												Player::OnInvis(currentPeer, 0, peernetid);
											}
										}
									}
								}
							}
							else if (str == "/subserver") {
								//Player::OnSendToServer(peer, 9393, 69, "127.0.0.1", 17093);


							}
							else if (str.substr(0, 6) == "/nick ") {
								if (getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) > 0) {
									((PlayerInfo*)(peer->data))->isNicked = true;
									string name = str.substr(6, cch.length() - 6 - 1);
									((PlayerInfo*)(event.peer->data))->displayName = name;
									((PlayerInfo*)(event.peer->data))->socialName = filterName2(name);
									GamePacket p3 = packetEnd(appendString(appendString(createPacket(), "OnNameChanged"), "`0`0" + name));
									memcpy(p3.data + 8, &(((PlayerInfo*)(peer->data))->netID), 4);
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
							}
							else if (str == "/nick") {
								if (getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) > 0) {
									((PlayerInfo*)(peer->data))->isNicked = false;
									string name = ((PlayerInfo*)(event.peer->data))->displayNamebackup;
									((PlayerInfo*)(event.peer->data))->displayName = name;
									((PlayerInfo*)(event.peer->data))->socialName = name;
									GamePacket p3 = packetEnd(appendString(appendString(createPacket(), "OnNameChanged"), "`0`0" + name));
									memcpy(p3.data + 8, &(((PlayerInfo*)(peer->data))->netID), 4);
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
							}
							else if (str.substr(0, 6) == "/flag ") {
								int lol = atoi(str.substr(6).c_str());
								if (lol < 0) continue;
								if (lol > coredatasize - 2) continue;
								GamePacket p2 = packetEnd(appendIntx(appendIntx(appendIntx(appendIntx(appendString(createPacket(), "OnGuildDataChanged"), 1), 2), lol), 3));
								memcpy(p2.data + 8, &(((PlayerInfo*)(peer->data))->netID), 4);
								ENetPacket * packet3 = enet_packet_create(p2.data,
									p2.len,
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
								delete p2.data;
							}
							else if (str.substr(0, 9) == "/weather ") {
								if (world->name != "ADMIN") {
									if (world->owner != "") {
										if (((PlayerInfo*)(peer->data))->userID == world->ownerId || isSuperAdmin(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass))

										{
											int weather = atoi(str.substr(9).c_str());
											if (weather < 0 || weather > 99) continue;
											world->weather = weather;
											ENetPeer* currentPeer;

											for (currentPeer = server->peers;
												currentPeer < &server->peers[server->peerCount];
												++currentPeer)
											{
												if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
													continue;
												if (isHere(peer, currentPeer))
												{
													GamePacket p1 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`oPlayer `2" + ((PlayerInfo*)(peer->data))->displayName + "`o has just changed the world's weather!"));
													ENetPacket * packet1 = enet_packet_create(p1.data,
														p1.len,
														ENET_PACKET_FLAG_RELIABLE);

													enet_peer_send(currentPeer, 0, packet1);
													delete p1.data;

													GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnSetCurrentWeather"), weather));
													ENetPacket * packet2 = enet_packet_create(p2.data,
														p2.len,
														ENET_PACKET_FLAG_RELIABLE);

													enet_peer_send(currentPeer, 0, packet2);
													delete p2.data;
													continue; /*CODE UPDATE /WEATHER FOR EVERYONE!*/
												}
											}
										}
									}
								}
							}
							else if (str == "/count") {
								int count = 0;
								ENetPeer * currentPeer;
								string name = "";
								for (currentPeer = server->peers;
									currentPeer < &server->peers[server->peerCount];
									++currentPeer)
								{
									if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
										continue;
									count++;
								}
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "There are " + std::to_string(count) + " people online out of 1024 limit."));
								ENetPacket * packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
								delete p.data;
								//enet_host_flush(server);
							}
							else if (str.substr(0, 5) == "/asb ") {
								if (!canSB(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) continue;
								cout << "ASB from " << ((PlayerInfo*)(peer->data))->rawName << " in world " << ((PlayerInfo*)(peer->data))->currentWorld << "with IP " << std::hex << peer->address.host << std::dec << " with message " << str.substr(5, cch.length() - 5 - 1) << endl;
								GamePacket p = packetEnd(appendInt(appendString(appendString(appendString(appendString(createPacket(), "OnAddNotification"), "interface/atomic_button.rttex"), str.substr(4, cch.length() - 4 - 1).c_str()), "audio/hub_open.wav"), 0));
								ENetPacket * packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								ENetPeer * currentPeer;
								for (currentPeer = server->peers;
									currentPeer < &server->peers[server->peerCount];
									++currentPeer)
								{
									if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
										continue;
									enet_peer_send(currentPeer, 0, packet);
								}

								//enet_host_flush(server);
								delete p.data;
							}


							else if (str.substr(0, 4) == "/sb ") {
								using namespace std::chrono;
								// crash
								if (((PlayerInfo*)(peer->data))->lastSB + 15000 < (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count())
								{
									((PlayerInfo*)(peer->data))->lastSB = (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count();
								}
								else {
									Player::OnConsoleMessage(peer, "Please wait a while before broadcasting again!");
									//enet_host_flush(server);
									continue;
								}

								string name = ((PlayerInfo*)(peer->data))->displayName;
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w** `5Super-Broadcast`` from `$`2" + name + "```` (in `$" + ((PlayerInfo*)(peer->data))->currentWorld + "``) ** :`` `# " + str.substr(4, cch.length() - 4 - 1)));
								string text = "action|play_sfx\nfile|audio/beep.wav\ndelayMS|0\n";
								BYTE* data = new BYTE[5 + text.length()];
								BYTE zero = 0;
								int type = 3;
								memcpy(data, &type, 4);
								memcpy(data + 4, text.c_str(), text.length());
								memcpy(data + 4 + text.length(), &zero, 1);
								ENetPeer * currentPeer;

								for (currentPeer = server->peers;
									currentPeer < &server->peers[server->peerCount];
									++currentPeer)
								{
									if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
										continue;
									if (!((PlayerInfo*)(currentPeer->data))->radio)
										continue;
									ENetPacket * packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);

									enet_peer_send(currentPeer, 0, packet);




									ENetPacket * packet2 = enet_packet_create(data,
										5 + text.length(),
										ENET_PACKET_FLAG_RELIABLE);

									enet_peer_send(currentPeer, 0, packet2);

									//enet_host_flush(server);
								}
								delete data;
								delete p.data;
							}
							else if (str.substr(0, 5) == "/jsb ") {
								using namespace std::chrono;
								if (((PlayerInfo*)(peer->data))->lastSB + 15000 < (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count())
								{
									((PlayerInfo*)(peer->data))->lastSB = (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count();
								}
								else {
									Player::OnConsoleMessage(peer, "Please wait a while before broadcasting again!");
									//enet_host_flush(server);
									continue;
								}

								string name = ((PlayerInfo*)(peer->data))->displayName;
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w** `5Super-Broadcast`` from `$`2" + name + "```` (in `4JAMMED``) ** :`` `# " + str.substr(5, cch.length() - 5 - 1)));
								string text = "action|play_sfx\nfile|audio/beep.wav\ndelayMS|0\n";
								BYTE* data = new BYTE[5 + text.length()];
								BYTE zero = 0;
								int type = 3;
								memcpy(data, &type, 4);
								memcpy(data + 4, text.c_str(), text.length());
								memcpy(data + 4 + text.length(), &zero, 1);
								ENetPeer * currentPeer;

								for (currentPeer = server->peers;
									currentPeer < &server->peers[server->peerCount];
									++currentPeer)
								{
									if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
										continue;
									if (!((PlayerInfo*)(currentPeer->data))->radio)
										continue;
									ENetPacket * packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);

									enet_peer_send(currentPeer, 0, packet);




									ENetPacket * packet2 = enet_packet_create(data,
										5 + text.length(),
										ENET_PACKET_FLAG_RELIABLE);

									enet_peer_send(currentPeer, 0, packet2);

									//enet_host_flush(server);
								}
								delete data;
								delete p.data;
							}


							else if (str.substr(0, 6) == "/radio") {
								GamePacket p;
								if (((PlayerInfo*)(peer->data))->radio) {
									p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "You won't see broadcasts anymore."));
									((PlayerInfo*)(peer->data))->radio = false;
								}
								else {
									p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "You will now see broadcasts again."));
									((PlayerInfo*)(peer->data))->radio = true;
								}

								ENetPacket * packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);

								enet_peer_send(peer, 0, packet);
								delete p.data;
								//enet_host_flush(server);
							}
							else if (str.substr(0, 6) == "/reset") {
								if (!isSuperAdmin(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) break;
								cout << "Restart from " << ((PlayerInfo*)(peer->data))->displayName << endl;
								GamePacket p = packetEnd(appendInt(appendString(appendString(appendString(appendString(createPacket(), "OnAddNotification"), "interface/science_button.rttex"), "Restarting soon!"), "audio/mp3/suspended.mp3"), 0));
								ENetPacket * packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								ENetPeer * currentPeer;
								for (currentPeer = server->peers;
									currentPeer < &server->peers[server->peerCount];
									++currentPeer)
								{
									if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
										continue;
									enet_peer_send(currentPeer, 0, packet);
								}
								delete p.data;
								//enet_host_flush(server);
							}


							else if (str == "/unmod")
							{
								//((PlayerInfo*)(peer->data))->canWalkInBlocks = false;
								//sendState(peer);

							}
							else if (str == "/alt") {
								GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnSetBetaMode"), 1));
								ENetPacket * packet2 = enet_packet_create(p2.data,
									p2.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet2);
								delete p2.data;
								//enet_host_flush(server);
							}
							else
								if (str == "/inventory")
								{
									sendInventory(peer, ((PlayerInfo*)(peer->data))->inventory);
								}
								else
									if (str.substr(0, 6) == "/give " || str.substr(0, 6) == "/item ")
									{

										int netID = ((PlayerInfo*)(peer->data))->netID;
										string args = str.substr(6, cch.length() - 6 - 1);
										string delimiter = " ";
										string arg1 = args.substr(0, args.find(delimiter));
										string arg2 = get_right_of_delim(args, delimiter);
										if (has_only_digits(arg1) == true && has_only_digits(arg2) == true) {
											try {
												int itemid = atoi(arg1.c_str());
												int count = atoi(arg2.c_str());

												addInventoryItem(peer, itemid, netID, count);
												SendTradeEffect(peer, itemid, netID, netID, 150);
												if (items.at(itemid).rarity != 999) {
													Player::OnConsoleMessage(peer, "`oGiven  `w" + arg2 + " " + items.at(itemid).name + " `oRarity: `w" + to_string(items.at(itemid).rarity) + "``");
												}
												else {
													Player::OnConsoleMessage(peer, "`oGiven  `w" + arg2 + " " + items.at(itemid).name + "``");
												}
											}
											catch (...) {
												Player::OnConsoleMessage(peer, "`4ERROR`w! `oSyntax error, usage: `w/give `o<item id> <amount>");
											}
										}
										else
										{
											Player::OnConsoleMessage(peer, "`4ERROR`w! `oSyntax error, usage: `w/give `o<item id> <amount>");
										}

										//Player::SendTilePickup(peer, itemid, ((PlayerInfo*)(peer->data))->netID, ((PlayerInfo*)(peer->data))->x / 32, ((PlayerInfo*)(peer->data))->y / 32, ((PlayerInfo*)(peer->data))->droppeditemcount, 50);

									}
									else

										if (str == "/vendtest")
										{
											/*int n = ((PlayerInfo*)(peer->data))->netID;
											((PlayerInfo*)(peer->data))->lastTradeNetID = n;
											((PlayerInfo*)(peer->data))->lastTradeName = ((PlayerInfo*)(peer->data))->displayName;
											//Player::OnStartTrade(peer, n, n);
											Player::OnPlayPositioned(peer, "audio/wood_break.wav", n, false, NULL);*/
											/*PlayerMoving data;
											//data.packetType = 0x14;
											data.packetType = 0x13;
											//data.characterState = 0x924; // animation
											data.characterState = 0x0; // animation
											data.x = 0;
											data.y = 0;
											data.punchX = 242;
											data.punchY = 242;
											data.XSpeed = 0;
											data.YSpeed = 0;
											data.netID = n;
											data.secondnetID = n;
											data.plantingTree = 950;
											SendPacketRaw(4, packTradeAnim(&data), 56, 0, peer, ENET_PACKET_FLAG_RELIABLE);*/



										}
										else
											if (str.substr(0, 7) == "/color ")
											{
												((PlayerInfo*)(peer->data))->skinColor = atoi(str.substr(6, cch.length() - 6 - 1).c_str());
												sendClothes(peer);
											}
							if (str.substr(0, 4) == "/who")
							{
								sendWho(peer);

							}
							if (isActioned) {

							}
							else if (str.length() > 0)
							{
								if (((PlayerInfo*)(peer->data))->taped == false) {
									sendChatMessage(peer, ((PlayerInfo*)(peer->data))->netID, str);
								}
								else {
									Player::OnConsoleMessage(peer, "`oYour mouth is currently too sticky to cause any sound! `w[DUCT-TAPED!]``");
								}
							}
						}
						if (!((PlayerInfo*)(event.peer->data))->hasLogon)
						{
							std::stringstream ss(GetTextPointerFromPacket(event.packet));
							std::string to;
							while (std::getline(ss, to, '\n')) {
								string id = to.substr(0, to.find("|"));
								string act = to.substr(to.find("|") + 1, to.length() - to.find("|") - 1);
								if (id == "tankIDName")
								{
									((PlayerInfo*)(event.peer->data))->tankIDName = act;
									((PlayerInfo*)(event.peer->data))->haveGrowId = true;
								}
								else if (id == "tankIDPass")
								{
									((PlayerInfo*)(event.peer->data))->tankIDPass = act;
								}
								else if (id == "requestedName")
								{
									((PlayerInfo*)(event.peer->data))->requestedName = act;
								}
								else if (id == "country")
								{
									((PlayerInfo*)(event.peer->data))->country = act;
								}
								else if (id == "doorID") {
									((PlayerInfo*)(event.peer->data))->doorID = act;
									
								}
								else if (id == "wk") {
									bool valid = true;
									if (act.substr(0, 4) == "NONE" || act.substr(1, 4) == "NONE" || act.substr(3, 4) == "NONE") valid = false;
									if (valid) {
										((PlayerInfo*)(event.peer->data))->sid = act;
										if (act.length() < 32) autoBan(peer, true, 1);
										if (act.length() > 36) autoBan(peer, true, 1);
									}

								}
								else if (id == "rid") {
									((PlayerInfo*)(event.peer->data))->rid = act;
									if (std::experimental::filesystem::exists("bans/rid/" + act + ".txt")) {
										((PlayerInfo*)(peer->data))->evadeRID = true;
									}
									if (act.length() < 32) autoBan(peer, true, 1);
									if (act.length() > 36) autoBan(peer, true, 1);

								}
								else if (id == "gid") {
									((PlayerInfo*)(event.peer->data))->gid = act;
								}
								else if (id == "aid") {
									((PlayerInfo*)(event.peer->data))->aid = act;
								}
								else if (id == "vid") {
									((PlayerInfo*)(event.peer->data))->vid = act;
								}
								else if (id == "zf") {
									if (act.length() < 4) autoBan(peer, true, 1);
									((PlayerInfo*)(event.peer->data))->zf = act;
								}
								else if (id == "game_version") {
									if (act.length() < 4) autoBan(peer, true, 1);
									((PlayerInfo*)(event.peer->data))->gameVersion = act;
								}
								else if (id == "platformID") {
									if (act.length() == 0) autoBan(peer, true, 1);
									((PlayerInfo*)(event.peer->data))->platformID = act;
								}
								else if (id == "mac") {
									((PlayerInfo*)(event.peer->data))->mac = act;
									if (act.length() < 16) autoBan(peer, true, 1);
									if (act.length() > 20) autoBan(peer, true, 1);
								}
								else if (id == "hash") {
									if (act.length() != 0) {
										if (act.length() < 6) autoBan(peer, true, 1);
										if (act.length() > 16) autoBan(peer, true, 1);
									}
								}
								else if (id == "hash2") {
									if (act.length() != 0) {
										if (act.length() < 6) autoBan(peer, true, 1);
										if (act.length() > 16) autoBan(peer, true, 1);
									}
								}
							}

							((PlayerInfo*)(event.peer->data))->hasLogon = true;
							if (itemdathash == 0) {
								enet_peer_disconnect_later(peer, 0);
							}
							if (configPort == 17093) {
								if (((PlayerInfo*)(event.peer->data))->platformID == "1") {
									GamePacket p = packetEnd(appendString(appendString(appendString(appendString(appendInt(appendString(createPacket(), "OnSuperMainStartAcceptLogonHrdxs47254722215a"), itemdathashNormal), "ubistatic-a.akamaihd.net"), "0098/CDNContent27/cache/"), "cc.cz.madkite.freedom org.aqua.gg idv.aqua.bulldog com.cih.gamecih2 com.cih.gamecih com.cih.game_cih cn.maocai.gamekiller com.gmd.speedtime org.dax.attack com.x0.strai.frep com.x0.strai.free org.cheatengine.cegui org.sbtools.gamehack com.skgames.traffikrider org.sbtoods.gamehaca com.skype.ralder org.cheatengine.cegui.xx.multi1458919170111 com.prohiro.macro me.autotouch.autotouch com.cygery.repetitouch.free com.cygery.repetitouch.pro com.proziro.zacro com.slash.gamebuster"), "proto=80|choosemusic=audio/mp3/ykoops.mp3|active_holiday=4"));
									ENetPacket * packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(peer, 0, packet);
									delete p.data;
								}
								else {
									Player::OnStartAcceptLogon(peer, itemdathash);
								}
							}




							if (!((PlayerInfo*)(event.peer->data))->haveGrowId)
							{
								((PlayerInfo*)(event.peer->data))->rawName = to_string(peer->address.host);
								((PlayerInfo*)(event.peer->data))->displayName = PlayerDB::fixColors(((PlayerInfo*)(event.peer->data))->requestedName.substr(0, ((PlayerInfo*)(event.peer->data))->requestedName.length() > 15 ? 15 : ((PlayerInfo*)(event.peer->data))->requestedName.length()) + "_" + to_string(peer->address.host));
							}
							else {

								((PlayerInfo*)(event.peer->data))->rawName = PlayerDB::getProperName(((PlayerInfo*)(event.peer->data))->tankIDName);
#ifdef REGISTRATION
								int logStatus = PlayerDB::playerLogin(peer, ((PlayerInfo*)(event.peer->data))->rawName, ((PlayerInfo*)(event.peer->data))->tankIDPass);
								if (logStatus == 1) {

								}
								else {
									Player::OnConsoleMessage(peer, "`wThis GrowID or Password doesn't seem `wvalid. `oIncase you `4lost `wyour `opassword, please contact the `qsupport`o, a `#moderator`o, or a `6developer`w.``");
									enet_peer_disconnect_later(peer, 0);
								}
#else

								((PlayerInfo*)(event.peer->data))->displayName = PlayerDB::fixColors(((PlayerInfo*)(event.peer->data))->tankIDName.substr(0, ((PlayerInfo*)(event.peer->data))->tankIDName.length() > 18 ? 18 : ((PlayerInfo*)(event.peer->data))->tankIDName.length()));
								if (((PlayerInfo*)(event.peer->data))->displayName.length() < 3) ((PlayerInfo*)(event.peer->data))->displayName = "Person that doesn't know how the name looks!";
#endif
							}
							for (char c : ((PlayerInfo*)(event.peer->data))->displayName) if (c < 0x20 || c>0x7A) ((PlayerInfo*)(event.peer->data))->displayName = "Bad characters in name, remove them!";

							int adminLevel = getAdminLevel(((PlayerInfo*)(event.peer->data))->rawName, ((PlayerInfo*)(event.peer->data))->tankIDPass);
							string displayname = ((PlayerInfo*)(event.peer->data))->displayNamebackup;
							if (((PlayerInfo*)(event.peer->data))->country.length() > 4)
							{
								((PlayerInfo*)(event.peer->data))->country = "us";
							}
							if (adminLevel == 1)
							{
								((PlayerInfo*)(event.peer->data))->country = "../cash_icon_overlay";
								((PlayerInfo*)(event.peer->data))->displayName = "`$" + displayname + "``";
								((PlayerInfo*)(event.peer->data))->displayNamebackup = "`$" + displayname + "``";
							}
							else if (adminLevel == 2) {
								((PlayerInfo*)(event.peer->data))->country = "../cash_icon_overlay";
								((PlayerInfo*)(event.peer->data))->displayName = "`q" + displayname + "``";
								((PlayerInfo*)(event.peer->data))->displayNamebackup = "`q" + displayname + "``";
								((PlayerInfo*)(peer->data))->mstate = 1;
							}
							else if (adminLevel == 3) {
								((PlayerInfo*)(event.peer->data))->displayName = "`#@" + displayname + "``";
								((PlayerInfo*)(event.peer->data))->displayNamebackup = "`#@" + displayname + "``";
								((PlayerInfo*)(event.peer->data))->mstate = 1;
								((PlayerInfo*)(event.peer->data))->boughtEC = true;
							}
							else if (adminLevel == 4) {
								((PlayerInfo*)(event.peer->data))->displayName = "`6@" + displayname + "``";
								((PlayerInfo*)(event.peer->data))->displayNamebackup = "`6@" + displayname + "``";
								((PlayerInfo*)(peer->data))->smstate = 1;
								((PlayerInfo*)(event.peer->data))->boughtEC = true;
							}
							else if (adminLevel == 5) {
								((PlayerInfo*)(event.peer->data))->displayName = "`4@" + displayname + "``";
								((PlayerInfo*)(event.peer->data))->displayNamebackup = "`4@" + displayname + "``";
								((PlayerInfo*)(peer->data))->smstate = 2;
								((PlayerInfo*)(event.peer->data))->boughtEC = true;
							}
							if (((PlayerInfo*)(event.peer->data))->displayName != "") {
								Player::OnConsoleMessage(peer, "`oWelcome back, `w" + ((PlayerInfo*)(event.peer->data))->displayName + "`o.``");
								/*if (configPort != 17093) {
									// TODO SUBSERVERS
									if (((PlayerInfo*)(peer->data))->hasJoinedFromSubServer == false)
									{
										string cname = ((PlayerInfo*)(peer->data))->doorID;
										((PlayerInfo*)(peer->data))->hasJoinedFromSubServer = true;
										((PlayerInfo*)(peer->data))->isIn = true;

										joinWorld(peer, cname);
										((PlayerInfo*)(peer->data))->currentWorld = cname;
										
										sendGazette(peer);
									}
								}*/
								GamePacket p2 = packetEnd(appendString(appendString(appendInt(appendString(createPacket(), "SetHasGrowID"), ((PlayerInfo*)(event.peer->data))->haveGrowId), ((PlayerInfo*)(peer->data))->tankIDName), ((PlayerInfo*)(peer->data))->tankIDPass));
								ENetPacket * packet2 = enet_packet_create(p2.data,
									p2.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet2);
								delete p2.data;
								Player::SetHasGrowID(peer, ((PlayerInfo*)(event.peer->data))->haveGrowId, ((PlayerInfo*)(peer->data))->tankIDName,
									((PlayerInfo*)(peer->data))->tankIDPass);
							}

						}
						string pStr = GetTextPointerFromPacket(event.packet);
						//if (strcmp(GetTextPointerFromPacket(event.packet), "action|enter_game\n") == 0 && !((PlayerInfo*)(event.peer->data))->isIn)
						if (pStr.substr(0, 17) == "action|enter_game" && !((PlayerInfo*)(event.peer->data))->isIn)
						{
#ifdef TOTAL_LOG
							cout << "And we are in!" << endl;
#endif				if (((PlayerInfo*)(event.peer->data))->isIn == true) continue;

							
							((PlayerInfo*)(event.peer->data))->isIn = true;
							
							ENetPeer* currentPeer;							
								sendWorldOffers(peer);
							

							// growmoji
							GamePacket p2ssw = packetEnd(appendString(appendInt(appendString(createPacket(), "OnEmoticonDataChanged"), 201560520), "(wl)|ā|1&(yes)|Ă|1&(no)|ă|1&(love)|Ą|1&(oops)|ą|1&(shy)|Ć|1&(wink)|ć|1&(tongue)|Ĉ|1&(agree)|ĉ|1&(sleep)|Ċ|1&(punch)|ċ|1&(music)|Č|1&(build)|č|1&(megaphone)|Ď|1&(sigh)|ď|1&(mad)|Đ|1&(wow)|đ|1&(dance)|Ē|1&(see-no-evil)|ē|1&(bheart)|Ĕ|1&(heart)|ĕ|1&(grow)|Ė|1&(gems)|ė|1&(kiss)|Ę|1&(gtoken)|ę|1&(lol)|Ě|1&(smile)|Ā|1&(cool)|Ĝ|1&(cry)|ĝ|1&(vend)|Ğ|1&(bunny)|ě|1&(cactus)|ğ|1&(pine)|Ĥ|1&(peace)|ģ|1&(terror)|ġ|1&(troll)|Ģ|1&(evil)|Ģ|1&(fireworks)|Ħ|1&(football)|ĥ|1&(alien)|ħ|1&(party)|Ĩ|1&(pizza)|ĩ|1&(clap)|Ī|1&(song)|ī|1&(ghost)|Ĭ|1&(nuke)|ĭ|1&(halo)|Į|1&(turkey)|į|1&(gift)|İ|1&(cake)|ı|1&(heartarrow)|Ĳ|1&(lucky)|ĳ|1&(shamrock)|Ĵ|1&(grin)|ĵ|1&(ill)|Ķ|1&"));
							ENetPacket * packet2ssw = enet_packet_create(p2ssw.data,
								p2ssw.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet2ssw);
							delete p2ssw.data;




							//enet_host_flush(server);

							PlayerInventory inventory;
							for (int i = 0; i < 200; i++)
							{
								InventoryItem it;
								it.itemID = (i * 2) + 2;
								it.itemCount = 200;
								inventory.items.push_back(it);
							}
							((PlayerInfo*)(event.peer->data))->inventory = inventory;
							sendGazette(peer);
							
						}
						if (strcmp(GetTextPointerFromPacket(event.packet), "action|refresh_item_data\n") == 0)
						{
							((PlayerInfo*)(peer->data))->updateReq++;
							if (((PlayerInfo*)(peer->data))->updateReq > 2) {
								enet_peer_reset(peer);
								continue;
							}
							if (((PlayerInfo*)(event.peer->data))->platformID != "1") {
								if (itemsDat != NULL) {
									Player::OnConsoleMessage(peer, "`oOne moment, updating item data...");
									ENetPacket * packet = enet_packet_create(itemsDat,
										itemsDatSize + 60,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(peer, 0, packet);
									//((PlayerInfo*)(peer->data))->isUpdating = true;
									//enet_peer_disconnect_later(peer, 0);
									//enet_host_flush(server);
								}
							}
							else {
								if (itemsDatNormal != NULL) {
									Player::OnConsoleMessage(peer, "`oOne moment, updating item data...");
									ENetPacket * packet = enet_packet_create(itemsDatNormal,
										itemsDatSizeNormal + 60,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(peer, 0, packet);
									//((PlayerInfo*)(peer->data))->isUpdating = true;
									//enet_peer_disconnect_later(peer, 0);
									//enet_host_flush(server);
								}
							}
							// TODO FIX refresh_item_data ^^^^^^^^^^^^^^
						}
						break;
					}
					default:
						cout << "[CMD] Unknown packet type " << messageType << endl;
						enet_peer_reset(peer);
						break;
					case 3:
					{
						bool isValidateReq = false;

						//cout << GetTextPointerFromPacket(event.packet) << endl;
						std::stringstream ss(GetTextPointerFromPacket(event.packet));
						std::string to;
						bool isJoinReq = false;
						while (std::getline(ss, to, '\n')) {
							string id = to.substr(0, to.find("|"));
							string act = to.substr(to.find("|") + 1, to.length() - to.find("|") - 1);
							if (id == "name" && isJoinReq)
							{

								joinWorld(peer, act);
							}
							else if (id == "name" && isValidateReq) {
								if (act.length() < 32) {
									isValidateReq = false;
									SendPacket(3, "action|world_validated\navailable|" + to_string(worldDB.getworldStatus(act)) + "\nworld_name|" + act, peer);
								}
							}
							if (id == "action")
							{
								if (act == "validate_world") {
									isValidateReq = true;
								}
								if (act == "join_request")
								{
									isJoinReq = true;
								}
								if (act == "quit_to_exit")
								{
									match.playersInGame--;
									((PlayerInfo*)(peer->data))->isInGame = false;
									sendPlayerLeave(peer, (PlayerInfo*)(event.peer->data));
									((PlayerInfo*)(peer->data))->currentWorld = "EXIT";
									sendWorldOffers(peer);
									Player::PlayAudio(peer, "audio/door_shut.wav", 0);

								}
								if (act == "quit")
								{
									if (((PlayerInfo*)(peer->data))->isWaitingForMatch) {
										((PlayerInfo*)(peer->data))->isWaitingForMatch = false;
										match.playersInQueue--;
									}
									if (((PlayerInfo*)(peer->data))->isInGame) {
										((PlayerInfo*)(peer->data))->isInGame = false;
										match.playersInGame--;
									}
									enet_peer_disconnect_later(peer, 0);
								}
							}
						}
						break;
					}
					case 4:
					{
						{
							if (!world) continue; // TESTINGWORLDANTI
							BYTE* tankUpdatePacket = GetStructPointerFromTankPacket(event.packet);

							if (tankUpdatePacket)
							{
								PlayerMoving* pMov = unpackPlayerMoving(tankUpdatePacket);
								if ((pMov->characterState >= 80 || pMov->characterState == 64) && pMov->characterState != 144 && pMov->characterState != 128 && pMov->characterState < 250) {
									if (((PlayerInfo*)(peer->data))->canWalkInBlocks == false)
									{
										((PlayerInfo*)(event.peer->data))->lavaLevel = ((PlayerInfo*)(event.peer->data))->lavaLevel + 1;

										if (((PlayerInfo*)(peer->data))->lavaLevel >= 5) {
											((PlayerInfo*)(peer->data))->lavaLevel = 0;
											int x = ((PlayerInfo*)(peer->data))->x;
											int y = ((PlayerInfo*)(peer->data))->y;
											for (int i = 0; i < world->width * world->height; i++)
											{
												if (world->items[i].foreground == 6) {
													x = (i % world->width) * 32;
													y = (i / world->width) * 32;
													//world->items[i].foreground = 8;
												}
											}
											playerRespawn(peer, false);
										}
									}
								}


								switch (pMov->packetType)
								{
								case 0:
									((PlayerInfo*)(event.peer->data))->x = pMov->x;
									((PlayerInfo*)(event.peer->data))->y = pMov->y;
									((PlayerInfo*)(event.peer->data))->isRotatedLeft = pMov->characterState & 0x10;
									sendPData(peer, pMov);
									if (!((PlayerInfo*)(peer->data))->joinClothesUpdated)
									{
										((PlayerInfo*)(peer->data))->joinClothesUpdated = true;
										sendState(peer, ((PlayerInfo*)(peer->data)));
										Player::OnSetBux(peer, ((PlayerInfo*)(peer->data))->gems, 1);
										updateAllClothes(peer);
										//Player::OnCountdownStart(peer, ((PlayerInfo*)(peer->data))->netID, 90, 100);
										if (((PlayerInfo*)(peer->data))->currentWorld == "PVP") {
											Player::OnCountdownStart(peer, ((PlayerInfo*)(peer->data))->netID, 420, 0);
										}
									}
									break;

								default:
									break;
								}
								PlayerMoving *data2 = unpackPlayerMoving(tankUpdatePacket);
								//logs << data2->characterState << "netID: " << data2->netID << "; " << "packetType: " << data2->packetType << "; " << "punchX: " << data2->punchX << "; " << "punchY: " << data2->punchY << "; " << "secondnetID: " << data2->secondnetID << "; " << "x: " << data2->x << "; " << "XSpeed: " << data2->XSpeed << "; " << "y: " << data2->y << "; " << "YSpeed: " << data2->YSpeed << ";" << endl;
								//logs.flush();
								//cout << data2->packetType << endl;						
								if (data2->packetType == 11)
								{
									//cout << pMov->x << ";" << pMov->y << ";" << pMov->plantingTree << ";" << pMov->punchX << endl					
									int playerditemcount = ((PlayerInfo*)(event.peer->data))->droppeditemcount;
									if (!world) continue;
									sendCollect(peer, ((PlayerInfo*)(event.peer->data))->netID, pMov->x, pMov->y, pMov->plantingTree);
								}


								if (data2->packetType == 25) {
									Player::OnAddNotification(peer, "`bNo cheat-engine kids! `w(`4Banned `ofor `w7 Days `o.`w)", "audio/hub_open.wav", "interface/atomic_button.rttex");
									autoBan(peer, false, 24 * 7);
								}
								if (data2->packetType == 23) {
									if (((PlayerInfo*)(peer->data))->currentWorld == "PVP") {
										if (((PlayerInfo*)(peer->data))->x != 0 && ((PlayerInfo*)(peer->data))->y != 0) {
											int puX = (int)((PlayerInfo*)(peer->data))->x / 32;
											int puY = (int)((PlayerInfo*)(peer->data))->y / 32;
											if (puX == ((PlayerInfo*)(peer->data))->respawnX / 32 && puY == ((PlayerInfo*)(peer->data))->respawnY / 32) continue;
											string killedBy = "(unknown)";
											string killedByrawname = "(unknown)";
											ENetPeer* currentPeer;
											for (currentPeer = server->peers;
												currentPeer < &server->peers[server->peerCount];
												++currentPeer)
											{
												if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
													continue;
												if (isHere(peer, currentPeer)) {
													if (((PlayerInfo*)(currentPeer->data))->lastPVPcoord || ((PlayerInfo*)(currentPeer->data))->lastPVPcoord2 || ((PlayerInfo*)(currentPeer->data))->lastPVPcoord3 || ((PlayerInfo*)(currentPeer->data))->lastPVPcoord4 || ((PlayerInfo*)(currentPeer->data))->lastPVPcoord5 || ((PlayerInfo*)(currentPeer->data))->lastPVPcoord6 || ((PlayerInfo*)(currentPeer->data))->lastPVPcoord7 == data2->plantingTree) {
														if (((PlayerInfo*)(currentPeer->data))->rawName == ((PlayerInfo*)(peer->data))->rawName) continue;
														killedBy = ((PlayerInfo*)(currentPeer->data))->displayName;
														killedByrawname = ((PlayerInfo*)(currentPeer->data))->rawName;
														((PlayerInfo*)(currentPeer->data))->lastPVPcoord = -1;
														((PlayerInfo*)(currentPeer->data))->lastPVPcoord2 = -1;
														((PlayerInfo*)(currentPeer->data))->lastPVPcoord3 = -1;
														((PlayerInfo*)(currentPeer->data))->lastPVPcoord4 = -1;
														((PlayerInfo*)(currentPeer->data))->lastPVPcoord5 = -1;
														((PlayerInfo*)(currentPeer->data))->lastPVPcoord6 = -1;
														((PlayerInfo*)(currentPeer->data))->lastPVPcoord7 = -1;


														int pTime = GetCurrentTimeInternalSeconds() - match.timePVPStarted;

														((PlayerInfo*)(peer->data))->health = ((PlayerInfo*)(peer->data))->health - 25;
														if (((PlayerInfo*)(peer->data))->health <= 0) {
															((PlayerInfo*)(currentPeer->data))->totalKills++;
															((PlayerInfo*)(currentPeer->data))->score = ((PlayerInfo*)(currentPeer->data))->score + 100;
															((PlayerInfo*)(peer->data))->health = 100;

															playerRespawn(peer, false);
															Player::OnConsoleMessage(peer, "`oYou were `4killed `oby `w" + killedBy + "`o.``");
															Player::OnCountdownStart(currentPeer, ((PlayerInfo*)(currentPeer->data))->netID, match.gameduration - pTime, ((PlayerInfo*)(currentPeer->data))->score);
														}


														break; // found player
														// soon resetting currentpeer's coordinates infos to 0, for safer/more accurate pvp system!
													}
												}
											}
										}
									}
								}
								if (data2->packetType == 7)
								{
									//cout << pMov->x << ";" << pMov->y << ";" << pMov->plantingTree << ";" << pMov->punchX << ";" << pMov->punchY << ";" << pMov->netID << ";" << pMov->secondnetID << ";" << endl;
									if (pMov->punchX < 0 || pMov->punchY < 0 || pMov->punchX > 100 || pMov->punchY > 100) continue;
									if (((PlayerInfo*)(event.peer->data))->currentWorld == "EXIT") continue;

									int x = pMov->punchX;
									int y = pMov->punchY;
									int tile = world->items[x + (y*world->width)].foreground;
									int netID = ((PlayerInfo*)(peer->data))->netID;
									if (tile == 6) {

										sendPlayerLeave(peer, (PlayerInfo*)(event.peer->data));
										((PlayerInfo*)(peer->data))->currentWorld = "EXIT";
										sendExit(peer);
										Player::PlayAudio(peer, "audio/door_shut.wav", 0);
									}
									else if (tile == 410 || tile == 1832 || tile == 1770) {
										((PlayerInfo*)(peer->data))->respawnX = x * 32;
										((PlayerInfo*)(peer->data))->respawnY = y * 32;
										Player::SetRespawnPos(peer, x, (world->width * y), netID);
									}
									else {
										Player::OnTalkBubble(peer, netID, "`w(too far away)``", 0, true);
										Player::OnZoomCamera(peer, 0, 0);
										Player::OnSetFreezeState(peer, 0, netID);
									}

									// lets take item
								}
								if (data2->packetType == 10)
								{
									//cout << pMov->x << ";" << pMov->y << ";" << pMov->plantingTree << ";" << pMov->punchX << ";" << pMov->punchY << ";" << pMov->characterState << endl;
									if (!world) continue;
									ItemDefinition def;
									try {
										def = getItemDef(pMov->plantingTree);
									}
									catch (int e) {
										goto END_CLOTHSETTER_FORCE;
									}
									int netid = ((PlayerInfo*)(event.peer->data))->netID;


									switch (def.clothType) {
									case 0:

										if (((PlayerInfo*)(event.peer->data))->cloth0 == pMov->plantingTree)
										{
											((PlayerInfo*)(event.peer->data))->cloth0 = 0;
											ENetPeer * currentPeer;

											for (currentPeer = server->peers;
												currentPeer < &server->peers[server->peerCount];
												++currentPeer)
											{
												if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
													continue;
												if (isHere(peer, currentPeer)) {
													Player::PlayAudio(currentPeer, "audio/change_clothes.wav", 135);
												}
											}
											break;
										}
										((PlayerInfo*)(event.peer->data))->cloth0 = pMov->plantingTree;
										ENetPeer * currentPeer;

										for (currentPeer = server->peers;
											currentPeer < &server->peers[server->peerCount];
											++currentPeer)
										{
											if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
												continue;
											if (isHere(peer, currentPeer)) {
												Player::PlayAudio(currentPeer, "audio/change_clothes.wav", 135);
											}
										}
										break;
									case 1:
										if (((PlayerInfo*)(event.peer->data))->cloth1 == pMov->plantingTree)
										{
											((PlayerInfo*)(event.peer->data))->cloth1 = 0;
											ENetPeer * currentPeer;

											for (currentPeer = server->peers;
												currentPeer < &server->peers[server->peerCount];
												++currentPeer)
											{
												if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
													continue;
												if (isHere(peer, currentPeer)) {
													Player::PlayAudio(currentPeer, "audio/change_clothes.wav", 135);
												}
											}
											break;
										}
										((PlayerInfo*)(event.peer->data))->cloth1 = pMov->plantingTree;


										for (currentPeer = server->peers;
											currentPeer < &server->peers[server->peerCount];
											++currentPeer)
										{
											if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
												continue;
											if (isHere(peer, currentPeer)) {
												Player::PlayAudio(currentPeer, "audio/change_clothes.wav", 135);
											}
										}
										break;
									case 2:
										if (((PlayerInfo*)(event.peer->data))->cloth2 == pMov->plantingTree)
										{
											((PlayerInfo*)(event.peer->data))->cloth2 = 0;
											ENetPeer * currentPeer;

											for (currentPeer = server->peers;
												currentPeer < &server->peers[server->peerCount];
												++currentPeer)
											{
												if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
													continue;
												if (isHere(peer, currentPeer)) {
													Player::PlayAudio(currentPeer, "audio/change_clothes.wav", 135);
												}
											}
											break;
										}
										((PlayerInfo*)(event.peer->data))->cloth2 = pMov->plantingTree;


										for (currentPeer = server->peers;
											currentPeer < &server->peers[server->peerCount];
											++currentPeer)
										{
											if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
												continue;
											if (isHere(peer, currentPeer)) {
												Player::PlayAudio(currentPeer, "audio/change_clothes.wav", 135);
											}
										}
										break;
									case 3:
										if (((PlayerInfo*)(event.peer->data))->cloth3 == pMov->plantingTree)
										{
											((PlayerInfo*)(event.peer->data))->cloth3 = 0;
											ENetPeer * currentPeer;

											for (currentPeer = server->peers;
												currentPeer < &server->peers[server->peerCount];
												++currentPeer)
											{
												if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
													continue;
												if (isHere(peer, currentPeer)) {
													Player::PlayAudio(currentPeer, "audio/change_clothes.wav", 135);
												}
											}
											break;
										}
										((PlayerInfo*)(event.peer->data))->cloth3 = pMov->plantingTree;


										for (currentPeer = server->peers;
											currentPeer < &server->peers[server->peerCount];
											++currentPeer)
										{
											if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
												continue;
											if (isHere(peer, currentPeer)) {
												Player::PlayAudio(currentPeer, "audio/change_clothes.wav", 135);
											}
										}
										break;
									case 4:
										if (((PlayerInfo*)(event.peer->data))->cloth4 == pMov->plantingTree)
										{
											((PlayerInfo*)(event.peer->data))->cloth4 = 0;
											ENetPeer * currentPeer;

											for (currentPeer = server->peers;
												currentPeer < &server->peers[server->peerCount];
												++currentPeer)
											{
												if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
													continue;
												if (isHere(peer, currentPeer)) {
													Player::PlayAudio(currentPeer, "audio/change_clothes.wav", 135);
												}
											}
											break;
										}
										((PlayerInfo*)(event.peer->data))->cloth4 = pMov->plantingTree;


										for (currentPeer = server->peers;
											currentPeer < &server->peers[server->peerCount];
											++currentPeer)
										{
											if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
												continue;
											if (isHere(peer, currentPeer)) {
												Player::PlayAudio(currentPeer, "audio/change_clothes.wav", 135);
											}
										}
										break;
									case 5:
										if (((PlayerInfo*)(event.peer->data))->cloth5 == pMov->plantingTree)
										{
											((PlayerInfo*)(event.peer->data))->cloth5 = 0;
											ENetPeer * currentPeer;

											for (currentPeer = server->peers;
												currentPeer < &server->peers[server->peerCount];
												++currentPeer)
											{
												if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
													continue;
												if (isHere(peer, currentPeer)) {
													Player::PlayAudio(currentPeer, "audio/change_clothes.wav", 135);
												}
											}
											break;
										}
										((PlayerInfo*)(event.peer->data))->cloth5 = pMov->plantingTree;


										for (currentPeer = server->peers;
											currentPeer < &server->peers[server->peerCount];
											++currentPeer)
										{
											if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
												continue;
											if (isHere(peer, currentPeer)) {
												Player::PlayAudio(currentPeer, "audio/change_clothes.wav", 135);
											}
										}
										break;
									case 6:
										if (((PlayerInfo*)(event.peer->data))->cloth6 == pMov->plantingTree)
										{

											if (((PlayerInfo*)(event.peer->data))->cloth6 == 9140) {
												Player::OnConsoleMessage(peer, "`oEstonian icicles melted! (`$Eesti `omod removed)``");
												((PlayerInfo*)(event.peer->data))->skinColor = 0x8295C3FF;
											}
											((PlayerInfo*)(event.peer->data))->cloth6 = 0;
											((PlayerInfo*)(event.peer->data))->canDoubleJump = false;
											sendState(peer, ((PlayerInfo*)(peer->data)));
											ENetPeer * currentPeer;

											for (currentPeer = server->peers;
												currentPeer < &server->peers[server->peerCount];
												++currentPeer)
											{
												if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
													continue;
												if (isHere(peer, currentPeer)) {
													Player::PlayAudio(currentPeer, "audio/change_clothes.wav", 135);
												}
											}
											break;


										}
										{

											((PlayerInfo*)(event.peer->data))->cloth6 = pMov->plantingTree;

											int item = pMov->plantingTree;


											if (item == 156 || item == 362 || item == 678 || item == 736 || item == 818 || item == 1206 || item == 1460 ||
												item == 1550 || item == 1574 || item == 1668 || item == 1672 || item == 1674 || item == 1784 || item == 1824
												|| item == 1936 || item == 1938 || item == 1970 || item == 2254 || item == 2256 || item == 2258 || item == 2260
												|| item == 2262 || item == 2264 || item == 2390 || item == 2392 || item == 3120 || item == 3308 || item == 3512
												|| item == 4534 || item == 4986 || item == 5754 || item == 6144 || item == 6334 || item == 6694 || item == 6818
												|| item == 6842 || item == 1934 || item == 3134 || item == 6004 || item == 1780 || item == 2158 || item == 2160
												|| item == 2162 || item == 2164 || item == 2166 || item == 2168 || item == 2438 || item == 2538 || item == 2778
												|| item == 3858 || item == 350 || item == 998 || item == 1738 || item == 2642 || item == 2982 || item == 3104 ||
												item == 3144 || item == 5738 || item == 3112 || item == 2722 || item == 3114 || item == 4970 || item == 4972 ||
												item == 5020 || item == 6284 || item == 4184 || item == 4628 || item == 5322 || item == 4112 || item == 4114 || item == 3442 || item == 9140) {

												if (item == 9140)
												{
													if (((PlayerInfo*)(event.peer->data))->boughtEC)
													{

														Player::OnConsoleMessage(peer, "`oEstonian icicles in your back! (`$Eesti `omod added)``");
														((PlayerInfo*)(event.peer->data))->skinColor = -49494;

													}
													else
													{
														Player::OnConsoleMessage(peer, "`4This item has to be `2purchased`o.");
														((PlayerInfo*)(event.peer->data))->cloth6 = 0;
														break;
													}
												}
												ENetPeer * currentPeer;

												for (currentPeer = server->peers;
													currentPeer < &server->peers[server->peerCount];
													++currentPeer)
												{
													if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
														continue;
													if (isHere(peer, currentPeer)) {
														Player::PlayAudio(currentPeer, "audio/change_clothes.wav", 135);
													}
												}


												((PlayerInfo*)(event.peer->data))->canDoubleJump = true;
											}
											else {
												((PlayerInfo*)(event.peer->data))->canDoubleJump = false;
											}
											// ^^^^ wings
											sendState(peer, ((PlayerInfo*)(peer->data)));
										}
										break;
									case 7:
										if (((PlayerInfo*)(event.peer->data))->cloth7 == pMov->plantingTree)
										{
											((PlayerInfo*)(event.peer->data))->cloth7 = 0;
											Player::PlayAudio(peer, "audio/change_clothes.wav", 135);
											break;
										}
										((PlayerInfo*)(event.peer->data))->cloth7 = pMov->plantingTree;


										for (currentPeer = server->peers;
											currentPeer < &server->peers[server->peerCount];
											++currentPeer)
										{
											if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
												continue;
											if (isHere(peer, currentPeer)) {
												Player::PlayAudio(currentPeer, "audio/change_clothes.wav", 135);
											}
										}
										break;
									case 8:


										if (((PlayerInfo*)(event.peer->data))->cloth8 == pMov->plantingTree)
										{
											((PlayerInfo*)(event.peer->data))->cloth8 = 0;
											break;
										}
										((PlayerInfo*)(event.peer->data))->cloth8 = pMov->plantingTree;
										break;
									case 9:


									default:


										if (
											def.id == 7166
											|| def.id == 5078 || def.id == 5080 || def.id == 5082 || def.id == 5084
											|| def.id == 5126 || def.id == 5128 || def.id == 5130 || def.id == 5132
											|| def.id == 5144 || def.id == 5146 || def.id == 5148 || def.id == 5150
											|| def.id == 5162 || def.id == 5164 || def.id == 5166 || def.id == 5168
											|| def.id == 5180 || def.id == 5182 || def.id == 5184 || def.id == 5186
											|| def.id == 7168 || def.id == 7170 || def.id == 7172 || def.id == 7174
											) {
											if (((PlayerInfo*)(event.peer->data))->cloth_ances == pMov->plantingTree) {

												((PlayerInfo*)(event.peer->data))->cloth_ances = 0;
												break;
											}

											((PlayerInfo*)(event.peer->data))->cloth_ances = pMov->plantingTree;

											ENetPeer * currentPeer;

											for (currentPeer = server->peers;
												currentPeer < &server->peers[server->peerCount];
												++currentPeer)
											{
												if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
													continue;
												if (isHere(peer, currentPeer)) {
													Player::PlayAudio(currentPeer, "audio/change_clothes.wav", 135);
												}
											}
										}
#ifdef TOTAL_LOG
										cout << "Invalid item activated: " << pMov->plantingTree << " by " << ((PlayerInfo*)(event.peer->data))->displayName << endl;
#endif
										break;
									}
									sendClothes(peer);

									// activate item
								END_CLOTHSETTER_FORCE:;
								}
								if (data2->packetType == 18)
								{
									sendPData(peer, pMov);
									// add talk buble
								}
								if (data2->punchX != -1 && data2->punchY != -1) {
									//cout << data2->packetType << endl;
									/*cout << "netID: " << data2->netID << endl;
									cout << "charStat: " << data2->characterState << endl;
									cout << "plantingTree: " << data2->plantingTree << endl;
									cout << "punchX: " << data2->punchX << endl;
									cout << "punchY: " << data2->punchY << endl;
									cout << "x: " << data2->x << endl;
									cout << "y: " << data2->y << endl;
									cout << "XSpeed: " << data2->XSpeed << endl;
									cout << "YSpeed: " << data2->YSpeed << endl;*/

									if (data2->packetType == 3)
									{
										if (((PlayerInfo*)(peer->data))->currentWorld == "PVP") {
											using namespace std::chrono;
											if (((PlayerInfo*)(peer->data))->lastHitTime + 100 < (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count())
											{
												int rank = 6;
												((PlayerInfo*)(peer->data))->lastHitTime = (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count();
												string pX = to_string(data2->punchX);
												string pY = to_string(data2->punchY);
												((PlayerInfo*)(peer->data))->lastPVPcoord = atoi((pY + pX).c_str());
												((PlayerInfo*)(peer->data))->lastPVPcoord2 = atoi((pY + pX).c_str()) + 1;
												((PlayerInfo*)(peer->data))->lastPVPcoord3 = atoi((pY + pX).c_str()) + 2;
												((PlayerInfo*)(peer->data))->lastPVPcoord4 = atoi((pY + pX).c_str()) - 2;
												((PlayerInfo*)(peer->data))->lastPVPcoord5 = atoi((pY + pX).c_str()) - 1;
												int pYMod1 = atoi(pY.c_str()) + 1;
												int pYMod2 = atoi(pY.c_str()) - 1;
												string pYMod1str = to_string(pYMod1);
												string pYMod2str = to_string(pYMod2);
												((PlayerInfo*)(peer->data))->lastPVPcoord6 = atoi((pYMod1str + pX).c_str());
												((PlayerInfo*)(peer->data))->lastPVPcoord7 = atoi((pYMod2str + pX).c_str());
												ENetPeer * currentPeer;
												for (currentPeer = server->peers;
													currentPeer < &server->peers[server->peerCount];
													++currentPeer)
												{
													if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
														continue;
													if (currentPeer == peer)
														continue;
													if (((PlayerInfo*)(currentPeer->data))->isInGame) {
														if (((PlayerInfo*)(peer->data))->score > ((PlayerInfo*)(currentPeer->data))->score) {
															rank--;
														}
													}
												}
												if (rank == 1) match.topOne = ((PlayerInfo*)(peer->data))->displayName;
												if (rank == 2) match.topTwo = ((PlayerInfo*)(peer->data))->displayName;
												if (rank == 3) match.topThree = ((PlayerInfo*)(peer->data))->displayName;
											}
										}







										using namespace std::chrono;
										if (data2->plantingTree == 18) {
											if (((PlayerInfo*)(peer->data))->lastPunchTime + 100 < (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count())
											{
												((PlayerInfo*)(peer->data))->lastPunchTime = (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count();
												sendTileUpdate(data2->punchX, data2->punchY, data2->plantingTree, ((PlayerInfo*)(event.peer->data))->netID, peer);

											}
										}
										else
										{
											sendTileUpdate(data2->punchX, data2->punchY, data2->plantingTree, ((PlayerInfo*)(event.peer->data))->netID, peer);
										}

									}
									else {

									}
									/*PlayerMoving data;
									//data.packetType = 0x14;
									data.packetType = 0x3;
									//data.characterState = 0x924; // animation
									data.characterState = 0x0; // animation
									data.x = data2->punchX;
									data.y = data2->punchY;
									data.punchX = data2->punchX;
									data.punchY = data2->punchY;
									data.XSpeed = 0;
									data.YSpeed = 0;
									data.netID = ((PlayerInfo*)(event.peer->data))->netID;
									data.plantingTree = data2->plantingTree;
									SendPacketRaw(4, packPlayerMoving(&data), 56, 0, peer, ENET_PACKET_FLAG_RELIABLE);
									cout << "Tile update at: " << data2->punchX << "x" << data2->punchY << endl;*/

								}
								delete data2;
								delete pMov;
							}

							else {
								cout << "Got bad tank packet";
							}
							/*char buffer[2048];
							for (int i = 0; i < event->packet->dataLength; i++)
							{
							sprintf(&buffer[2 * i], "%02X", event->packet->data[i]);
							}
							cout << buffer;*/
						}
					}
					break;
					case 5:
						break;
					case 6:
						//cout << GetTextPointerFromPacket(event.packet) << endl;
						break;
					}
					enet_packet_destroy(event.packet);
					break;
				}
				case ENET_EVENT_TYPE_DISCONNECT:
#ifdef TOTAL_LOG
					printf("Peer disconnected.\n");
#endif

					/* Reset the peer's client information. */
					/*ENetPeer* currentPeer;
					for (currentPeer = server->peers;
						currentPeer < &server->peers[server->peerCount];
						++currentPeer)
					{
						if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
							continue;

						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "Player `o" + ((PlayerInfo*)(event.peer->data))->tankIDName + "`o just left the game..."));
						ENetPacket * packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(currentPeer, 0, packet);
						enet_host_flush(server);
					}*/
					savePlayer(peer);
					if (((PlayerInfo*)(peer->data))->isIn) {
						sendPlayerLeave(peer, (PlayerInfo*)(event.peer->data));
					}
					if (((PlayerInfo*)(peer->data))->isWaitingForMatch) {
						match.playersInQueue--;
					}
					if (((PlayerInfo*)(peer->data))->isInGame) {
						match.playersInGame--;
					}
					((PlayerInfo*)(event.peer->data))->inventory.items.clear();
					delete (PlayerInfo*)event.peer->data;
					event.peer->data = NULL;
				}
			}
		}

	}
	cout << "Program ended??? Huh?" << endl;
	while (1);
	return 0;
}


