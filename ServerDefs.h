#pragma once
#include "enet/enet.h"
#include <Windows.h>
#include <vector>
#include <mysql.h>
#pragma warning(disable : 4996)
using namespace std;


const char *ip = "remotemysql.com";
const char *user = "UV1pzzVY0O";
const char *pass = "vXLd6UMrzX";
const char *database = "UV1pzzVY0O";
ENetHost * server;
int cId = 1;
MYSQL* conn;
MYSQL_RES* res;

BYTE* itemsDat = 0;
int itemsDatSize = 0;
int itemdathash;

BYTE* itemsDatNormal = 0;
int itemsDatSizeNormal = 0;
int itemdathashNormal;

int coredatasize = 0;
int totaluserids = 0;

string filterName2(string password) {

	string filteredpass = "";
	for (int i = 0; i < password.length(); i++) {
		string ch = password.substr(i, 1); // always take 1 character, and move next. EXAMPLE: we got password 12345, it will take first 1 and check, then 2 and check, and 3 and check, 4 and check, 5 and ccheck. it will scan ALL characters if bad symbols etc. because i is always getting a higher number cuz we said i++
		if (ch != "a" && ch != "A" && ch != "b" && ch != "B" && ch != "c" && ch != "C" && ch != "d" && ch != "D" && ch != "e" && ch != "E"
			&& ch != "f" && ch != "F" && ch != "g" && ch != "G" && ch != "h" && ch != "H" && ch != "i" && ch != "I" && ch != "j" && ch != "J"
			&& ch != "k" && ch != "K" && ch != "l" && ch != "L" && ch != "m" && ch != "M" && ch != "n" && ch != "N" && ch != "o" && ch != "O" &&
			ch != "p" && ch != "P" && ch != "q" && ch != "Q" && ch != "r" && ch != "R" && ch != "s" && ch != "S" && ch != "t" && ch != "T" && ch != "u" && ch != "U"
			&& ch != "v" && ch != "V" && ch != "w" && ch != "W" && ch != "x" && ch != "X" && ch != "y" && ch != "Y" && ch != "z" && ch != "Z" && ch != "0" && ch != "1" && ch != "2"
			&& ch != "3" && ch != "4" && ch != "5" && ch != "6" && ch != "7" && ch != "8" && ch != "9" && ch != "!" && ch != "." && ch != "@") {


		}
		else
		{
			filteredpass = filteredpass + ch;
		}
	}
	return filteredpass;
}

bool serverIsFrozen = false;

// items stuff
void decodeName(char* src, int len, int itemID, char* dest) {
	const char key[] = "PBG892FXX982ABC*";
	for (int i = 0; i < len; i++) {
		dest[i] = src[i] ^ key[(i + itemID) % 16];
	}
}

ofstream logs;


uint32_t HashString(unsigned char* str, int len)
{
	if (!str) return 0;

	unsigned char* n = (unsigned char*)str;
	uint32_t acc = 0x55555555;

	if (len == 0)
	{
		while (*n)
			acc = (acc >> 27) + (acc << 5) + *n++;
	}
	else
	{
		for (int i = 0; i < len; i++)
		{
			acc = (acc >> 27) + (acc << 5) + *n++;
		}
	}
	return acc;

}

unsigned char* getA(string fileName, int* pSizeOut, bool bAddBasePath, bool bAutoDecompress)
{
	unsigned char* pData = NULL;
	FILE* fp = fopen(fileName.c_str(), "rb");
	if (!fp)
	{
		cout << "File not found" << endl;
		if (!fp) return NULL;
	}

	fseek(fp, 0, SEEK_END);
	*pSizeOut = ftell(fp);
	fseek(fp, 0, SEEK_SET);

	pData = (unsigned char*)new unsigned char[((*pSizeOut) + 1)];
	if (!pData)
	{
		printf("Out of memory opening %s?", fileName.c_str());
		return 0;
	}
	pData[*pSizeOut] = 0;
	fread(pData, *pSizeOut, 1, fp);
	fclose(fp);

	return pData;
}

struct itemDataStruct {
	string name;
	string texturefile;
	string audiofile;
	int id;
	uint8_t editableType;
	uint8_t category;
	uint8_t type;
	uint8_t solid;
	uint16_t rarity;
	uint32_t color1;
	uint32_t color2;
	uint8_t textureX;
	uint8_t textureY;
	uint8_t textureType;
	uint8_t hardness;
	uint16_t audioVol;
	uint32_t texturehash;
	uint32_t audiohash;
	uint8_t seedBase;
	uint8_t seedOverlay;
	uint8_t treeBase;
	uint8_t treeOverlay;
};

enum editableType {
	consumable = 20
};

enum itemType {
	clothing = 20,
	background = 18,
	sheet_music = 28,
	lock = 3
};

template<typename T>
void Remove(std::basic_string<T> & Str, const T * CharsToRemove)
{
	std::basic_string<T>::size_type pos = 0;
	while ((pos = Str.find_first_of(CharsToRemove, pos)) != std::basic_string<T>::npos)
	{
		Str.erase(pos, 1);
	}
}

vector<itemDataStruct> items;
void serializeItems();
itemDataStruct getItem(int id) {
	if (itemsDat == NULL) {
		itemDataStruct ret;
		ret.id = -1;
		return ret;
	}
	uint8_t* itemsPtr = itemsDat + 60;
	itemsPtr += 4;
	while (true) {
		itemsPtr += *(uint16_t*)itemsPtr + 2;

		if (*(uint16_t*)itemsPtr == id) {
			itemDataStruct item;

			item.id = *(uint16_t*)itemsPtr;
			itemsPtr += 2;

			itemsPtr += 2; // ??

			item.editableType = *(uint8_t*)itemsPtr++;
			item.category = *(uint8_t*)itemsPtr++;
			item.type = *(uint8_t*)itemsPtr++;
			itemsPtr++;

			int nameLen = *(uint16_t*)itemsPtr;
			itemsPtr += 2;
			string name;
			name.resize(nameLen);
			decodeName((char*)itemsPtr, nameLen, id, &name[0]);
			item.name = name;
			itemsPtr += nameLen;

			int textureLen = *(uint16_t*)itemsPtr;
			itemsPtr += 2;
			string texturefile;
			texturefile.resize(textureLen);
			memcpy(&texturefile[0], itemsPtr, textureLen);
			item.texturefile = texturefile;
			itemsPtr += textureLen;

			item.texturehash = *(uint32_t*)itemsPtr;
			itemsPtr += 4;

			itemsPtr += 5; // ??

			item.textureX = *(uint8_t*)itemsPtr++;
			item.textureY = *(uint8_t*)itemsPtr++;
			item.textureType = *(uint8_t*)itemsPtr;
			itemsPtr += 2;

			item.solid = *(uint8_t*)itemsPtr++;

			item.hardness = *(uint8_t*)itemsPtr++;

			itemsPtr += 1; // mystery_3
			itemsPtr += 4; // ??

			item.rarity = *(uint16_t*)itemsPtr;
			itemsPtr += 2;

			itemsPtr += 1; // ??

			int audioLen = *(uint16_t*)itemsPtr;
			itemsPtr += 2;
			string audiofile;
			audiofile.resize(audioLen);
			memcpy(&audiofile[0], itemsPtr, audioLen);
			item.audiofile = audiofile;
			itemsPtr += audioLen;

			item.audiohash = *(uint32_t*)itemsPtr;
			itemsPtr += 4;
			item.audioVol = *(uint16_t*)itemsPtr;
			itemsPtr += 2;

			itemsPtr += 16; // ??

			item.seedBase = *(uint8_t*)itemsPtr++;
			item.seedOverlay = *(uint8_t*)itemsPtr++;
			item.treeBase = *(uint8_t*)itemsPtr++;
			item.treeOverlay = *(uint8_t*)itemsPtr++;

			item.color1 = *(uint32_t*)itemsPtr;
			itemsPtr += 4;
			item.color2 = *(uint32_t*)itemsPtr;
			itemsPtr += 4;

			return item;
		}
		else {
			itemsPtr += 8;
			itemsPtr += *(uint16_t*)itemsPtr + 2;
			itemsPtr += *(uint16_t*)itemsPtr + 2;
			itemsPtr += 23;
			itemsPtr += *(uint16_t*)itemsPtr + 2;
			itemsPtr += 8;
			for (int i = 0; i < 4; i++) itemsPtr += *(uint16_t*)itemsPtr + 2;
			itemsPtr += 24;
			itemsPtr += *(uint16_t*)itemsPtr + 2; // not sure about this
			itemsPtr += *(uint16_t*)itemsPtr + 2;
			itemsPtr += *(uint16_t*)itemsPtr + 2;
			itemsPtr += *(uint16_t*)itemsPtr + 2;
			itemsPtr += 78;
		}

		if (itemsPtr - itemsDat >= itemsDatSize) {
			itemDataStruct item;
			item.id = -1;
			return item;
		}
	}
}

void serializeItems() {
	printf("Loading all items...\n");
	int i = 0;
	while (true) {
		itemDataStruct item = getItem(i++);
		if (item.id == -1) break;
		items.push_back(item);
	}
	printf("Finished loading all items...\n");
}

