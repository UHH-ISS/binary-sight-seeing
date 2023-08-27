#include "enums.h"

namespace enum_functions
{
    std::string TraceLineContent_ToString(TraceLineContent tlc)
    {
        switch (tlc)
        {
            case TraceLineContent::REGS: return "REGS";
            case TraceLineContent::MEM_R: return "MEM_R";
            case TraceLineContent::MEM_W: return "MEM_W";
            case TraceLineContent::SOCKET_ENTRY: return "SOCKET_ENTRY";
            case TraceLineContent::SOCKET_EXIT: return "SOCKET_EXIT";
            default: return "ERROR_TRACE_LINE_CONTENT";
        }
    }
    std::string WrappedCall_ToString(WrappedCall wc)
    {
        switch (wc)
        {
            case WrappedCall::SENDTO: return "SENDTO";
            case WrappedCall::WSA_SENDTO: return "WSA_SENDTO";
            case WrappedCall::WSA_CONNECT: return "WSA_CONNECT";
            case WrappedCall::CONNECT: return "CONNECT";
            case WrappedCall::RECVFROM: return "RECVFROM";
            case WrappedCall::WSA_RECVFROM: return "WSA_RECVFROM";
            case WrappedCall::ACCEPT: return "ACCEPT";
            case WrappedCall::WSA_ACCEPT: return "WSA_ACCEPT";
            default: return "ERROR_WRAPPED_CALL";
        }
    }
}