#pragma once

namespace WIN {
#include <WinSock2.h>
#include <Windows.h>
}

// Redefine the INVALID_SOCKET macro.
// Otherwise it will use SOCKET instead
// of WIN::SOCKET which will result in a
// compiler error. 
#define INVALID_SOCKET  (WIN::SOCKET)(~0)