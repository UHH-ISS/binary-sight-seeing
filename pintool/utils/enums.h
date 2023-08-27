#pragma once
#include <string>

enum ByteOrder {
    LSB_FIRST,
    MSB_FIRST
};

enum TraceLineContent {
    REGS = 0,
    MEM_R = 1,
    MEM_W = 2,
    SOCKET_ENTRY = 3,
    SOCKET_EXIT = 4,
};

enum WrappedCall {
    SENDTO = 0,
    WSA_SENDTO = 1,
    WSA_CONNECT = 2,
    CONNECT = 3,
    RECVFROM = 4,
    WSA_RECVFROM = 5,
    ACCEPT = 6,
    WSA_ACCEPT = 7
};

namespace enum_functions
{
    std::string TraceLineContent_ToString(TraceLineContent tlc);
    std::string WrappedCall_ToString(WrappedCall wc);
}