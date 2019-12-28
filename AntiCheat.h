#pragma once
#include "GTV3Queue.h"
#include "GamePacket.h"
#include "ServerDefs.h"
#include "PlayerDefs.h"
#include <Windows.h>

int lastIPLogon = 0;

long long int lastIPWait = 0;
int itemsize = 9142;

struct PlayerCheat {
	long long int lastSBSafe = 0;
};