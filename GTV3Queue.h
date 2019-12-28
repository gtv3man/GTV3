#pragma once
#include "enet/enet.h"
#include <Windows.h>
#include <vector>
#include "PlayerDefs.h"
#include "GamePacket.h"
#include "ServerDefs.h"
#include <chrono>

struct PVPQueue {
	// queue
	bool isMatchRunning = false;
	int inTeamRed = 0;
	int inTeamBlue = 0;
	int playersInQueue = 0;
	int playersInGame = 0;
	int gameduration = 420;
	long long timePVPStarted = 0;
	// player
	string topOne = "";
	string topTwo = "";
	string topThree = "";
	string topFour = "";
	string topFive = "";
	string topSix = "";
};

PVPQueue match;