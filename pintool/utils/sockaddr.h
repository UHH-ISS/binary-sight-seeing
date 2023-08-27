#pragma once



#ifdef _WIN32
#include "windows.h"
using WIN::sockaddr;
using WIN::sockaddr_in;

#elif linux
namespace LINUX
{
    #include "linux/socket.h"
    #include "linux/in.h"

    typedef struct sockaddr sockaddr;
    typedef struct sockaddr_in sockaddr_in;
} // namespace LINUX

using LINUX::sockaddr;
using LINUX::sockaddr_in;

#endif