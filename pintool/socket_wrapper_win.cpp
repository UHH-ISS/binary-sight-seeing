#include "socket_wrapper.h"

#ifdef _WIN32

#include "utils/windows.h"

#define REPLACE_FUNCTION_COMMON_ARGS \
ADDRINT return_addr, const CONTEXT *ctxt, THREADID tid, AFUNPTR orig_funptr

#define REPLACE_SIGNATURE(fun, proto, args) \
RTN rtn = RTN_FindByAddress(IMG_LowAddress(img) + SYM_Value(sym)); \
if (RTN_Valid(rtn)) \
{ \
    RTN_ReplaceSignature(rtn, (AFUNPTR) fun, \
        IARG_RETURN_IP, \
        IARG_CONST_CONTEXT, \
        IARG_THREAD_ID, \
        IARG_ORIG_FUNCPTR, \
        IARG_PROTOTYPE, proto, \
        args, \
        IARG_END); \
}
#define ARGS_FUNCARG_10 ARGS_FUNCARG_9, IARG_FUNCARG_ENTRYPOINT_VALUE, 9
#define ARGS_FUNCARG_9  ARGS_FUNCARG_8, IARG_FUNCARG_ENTRYPOINT_VALUE, 8
#define ARGS_FUNCARG_8  ARGS_FUNCARG_7, IARG_FUNCARG_ENTRYPOINT_VALUE, 7
#define ARGS_FUNCARG_7  ARGS_FUNCARG_6, IARG_FUNCARG_ENTRYPOINT_VALUE, 6
#define ARGS_FUNCARG_6  ARGS_FUNCARG_5, IARG_FUNCARG_ENTRYPOINT_VALUE, 5
#define ARGS_FUNCARG_5  ARGS_FUNCARG_4, IARG_FUNCARG_ENTRYPOINT_VALUE, 4
#define ARGS_FUNCARG_4  ARGS_FUNCARG_3, IARG_FUNCARG_ENTRYPOINT_VALUE, 3
#define ARGS_FUNCARG_3  ARGS_FUNCARG_2, IARG_FUNCARG_ENTRYPOINT_VALUE, 2
#define ARGS_FUNCARG_2  ARGS_FUNCARG_1, IARG_FUNCARG_ENTRYPOINT_VALUE, 1
#define ARGS_FUNCARG_1  IARG_FUNCARG_ENTRYPOINT_VALUE, 0

static MessageIpc *message_ipc;

void log_sockaddr(ADDRINT return_addr, WIN::sockaddr* sockaddr, WrappedCall wrapped_call, TraceLineContent tlc, bool send_ipc)
{
    if (sockaddr == NULL) return;
    if (sockaddr->sa_family != AF_INET) return;
    PIN_LockClient();
    PIN_MutexLock(&trace_mutex);
    WIN::sockaddr_in* sockaddr_in = reinterpret_cast<WIN::sockaddr_in*>(sockaddr);
	char socket_entry_log[1 + 4 + 4]; // type, ip, return_addr
	uint8_t addr[4];
	unsigned short port_wrong_byte_order;

	socket_entry_log[0] = tlc;
    *((ADDRINT *)&socket_entry_log[5]) = return_addr;
	
	PIN_SafeCopy(addr, &(sockaddr_in->sin_addr), 4); // Read destination IP (only ipv4)
	PIN_SafeCopy(&port_wrong_byte_order, &(sockaddr_in->sin_port), 2); // Read destination port
    unsigned short port =
        (port_wrong_byte_order >> 8) |
        ((0x00FF & port_wrong_byte_order) << 8);

	std::ostringstream oss;
    oss << "[SOCKET_WRAPPER] ";
    oss << enum_functions::TraceLineContent_ToString(tlc) << ' ';
    oss << enum_functions::WrappedCall_ToString(wrapped_call) << ' ';
	for (int i = 0; i < 3; ++i) {
		oss << unsigned(addr[i]) << ".";
		socket_entry_log[i+1] = addr[i];
	}
	oss << unsigned(addr[3]) << ':' << port << " -> " << return_addr << ' ';
    IMG img = IMG_FindByAddress(return_addr);
    if (IMG_Valid(img))
    {
        oss << '(' << IMG_Name(img) << ')' << std::endl;
    }
    else
    {
        oss << "(no image)\n";
    }
	socket_entry_log[4] = addr[3];
	
	std::string socket_log_string(socket_entry_log, 1 + 4 + 4);
	global_binary_logger->log("\xA1\xA2\xA3\xA4" + socket_log_string);
	global_text_logger->log(oss.str());

	if (message_ipc != nullptr && send_ipc) {
		message_ipc->notify_socket_call(wrapped_call, addr, port);
		message_ipc->await_reply();
	}

    PIN_UnlockClient();
    PIN_MutexUnlock(&trace_mutex);
}

//////// accept
PROTO proto_accept;
PROTO proto_wsaaccept;
void generate_accept_proto() {
    proto_accept = PROTO_Allocate(
        PIN_PARG(WIN::SOCKET), CALLINGSTD_STDCALL, "accept",
        PIN_PARG(WIN::SOCKET), PIN_PARG(WIN::sockaddr *), PIN_PARG(int *),
        PIN_PARG_END()
    );
    proto_wsaaccept = PROTO_Allocate(
        PIN_PARG(WIN::SOCKET), CALLINGSTD_STDCALL, "WSAAccept",
        PIN_PARG(WIN::SOCKET), PIN_PARG(WIN::sockaddr *), PIN_PARG(int *),
        PIN_PARG(WIN::LPCONDITIONPROC), PIN_PARG(WIN::DWORD_PTR),
        PIN_PARG_END()
    );
}
// https://docs.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-accept
WIN::SOCKET replace_accept(REPLACE_FUNCTION_COMMON_ARGS,
                           WIN::SOCKET s, WIN::sockaddr *addr, int *addrlen) {
	WIN::SOCKET res;
    PIN_CallApplicationFunction(ctxt, tid, CALLINGSTD_STDCALL, orig_funptr, NULL,
        PIN_PARG(WIN::SOCKET), &res,
        PIN_PARG(WIN::SOCKET), s,
        PIN_PARG(WIN::sockaddr *), addr,
        PIN_PARG(int *), addrlen,
        PIN_PARG_END());
    log_sockaddr(return_addr, addr, WrappedCall::ACCEPT, TraceLineContent::SOCKET_EXIT, true);
    return res;
}
// https://docs.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsaaccept
WIN::SOCKET replace_wsaaccept(REPLACE_FUNCTION_COMMON_ARGS,
                              WIN::SOCKET s, WIN::sockaddr *addr, int *addrlen,
                              WIN::LPCONDITIONPROC condition, WIN::DWORD_PTR callback_data) {
	WIN::SOCKET res;
	PIN_CallApplicationFunction(ctxt, tid, CALLINGSTD_STDCALL, orig_funptr, NULL,
        PIN_PARG(WIN::SOCKET), &res,
        PIN_PARG(WIN::SOCKET), s,
        PIN_PARG(WIN::sockaddr *), addr,
        PIN_PARG(int *), addrlen,
        PIN_PARG(WIN::LPCONDITIONPROC), condition,
        PIN_PARG(WIN::DWORD_PTR), callback_data,
        PIN_PARG_END());
    log_sockaddr(return_addr, addr, WrappedCall::WSA_ACCEPT, TraceLineContent::SOCKET_ENTRY, true);
    return res;
}

//////// connect
PROTO proto_connect;
PROTO proto_wsaconnect;
void generate_connect_proto() {
    proto_connect = PROTO_Allocate(
        PIN_PARG(int), CALLINGSTD_STDCALL, "connect",
        PIN_PARG(WIN::SOCKET), PIN_PARG(WIN::sockaddr *), PIN_PARG(int),
        PIN_PARG_END()
    );
    proto_wsaconnect = PROTO_Allocate(
        PIN_PARG(int), CALLINGSTD_STDCALL, "WSAConnect",
        PIN_PARG(WIN::SOCKET), PIN_PARG(WIN::sockaddr *), PIN_PARG(int),
        PIN_PARG(WIN::LPWSABUF), PIN_PARG(WIN::LPWSABUF),
        PIN_PARG(WIN::LPQOS), PIN_PARG(WIN::LPQOS),
        PIN_PARG_END()
    );
}

// https://docs.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-connect
int replace_connect(REPLACE_FUNCTION_COMMON_ARGS,
                    WIN::SOCKET s, WIN::sockaddr *name, int namelen) {
    log_sockaddr(return_addr, name, WrappedCall::CONNECT, TraceLineContent::SOCKET_ENTRY, true);
    int res;
    PIN_CallApplicationFunction(ctxt, tid, CALLINGSTD_STDCALL, orig_funptr, NULL,
        PIN_PARG(int), &res,
        PIN_PARG(WIN::SOCKET), s,
        PIN_PARG(WIN::sockaddr *), name,
        PIN_PARG(int), namelen,
        PIN_PARG_END());
    log_sockaddr(return_addr, name, WrappedCall::CONNECT, TraceLineContent::SOCKET_EXIT, false);

    return res;
}
// https://docs.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsaconnect
int replace_wsaconnect(REPLACE_FUNCTION_COMMON_ARGS,
                       WIN::SOCKET s, WIN::sockaddr *name, int namelen,
                       WIN::LPWSABUF lpCallerData, WIN::LPWSABUF lpCalleeData,
                       WIN::LPQOS lpSQOS, WIN::LPQOS lpGQOS) {
    log_sockaddr(return_addr, name, WrappedCall::WSA_CONNECT, TraceLineContent::SOCKET_ENTRY, true);
    int res;
    PIN_CallApplicationFunction(ctxt, tid, CALLINGSTD_STDCALL, orig_funptr, NULL,
        PIN_PARG(int), &res,
        PIN_PARG(WIN::SOCKET), s,
        PIN_PARG(WIN::sockaddr *), name,
        PIN_PARG(int), namelen,
        PIN_PARG(WIN::LPWSABUF), lpCallerData,
        PIN_PARG(WIN::LPWSABUF), lpCalleeData,
        PIN_PARG(WIN::LPQOS), lpSQOS, 
        PIN_PARG(WIN::LPQOS), lpGQOS,
        PIN_PARG_END());
    log_sockaddr(return_addr, name, WrappedCall::WSA_CONNECT, TraceLineContent::SOCKET_EXIT, false);

    return res;
}

//////// recvfrom
PROTO proto_recvfrom;
PROTO proto_wsarecvfrom;
void generate_recvfrom_proto() {
    proto_recvfrom = PROTO_Allocate(
        PIN_PARG(int), CALLINGSTD_STDCALL, "recvfrom",
        PIN_PARG(WIN::SOCKET), PIN_PARG(char *),
        PIN_PARG(int), PIN_PARG(int),
        PIN_PARG(WIN::sockaddr *), PIN_PARG(int),
        PIN_PARG_END()
    );
    proto_wsarecvfrom = PROTO_Allocate(
        PIN_PARG(int), CALLINGSTD_STDCALL, "WSARecvFrom",
        PIN_PARG(WIN::SOCKET), PIN_PARG(WIN::LPWSABUF),
        PIN_PARG(WIN::DWORD), PIN_PARG(WIN::LPDWORD),
        PIN_PARG(WIN::LPDWORD), PIN_PARG(WIN::sockaddr *),
        PIN_PARG(WIN::LPINT), PIN_PARG(WIN::LPWSAOVERLAPPED),
        PIN_PARG(WIN::LPWSAOVERLAPPED_COMPLETION_ROUTINE),
        PIN_PARG_END()
    );
}
// https://docs.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-recvfrom
int replace_recvfrom(REPLACE_FUNCTION_COMMON_ARGS,
                     WIN::SOCKET s, char *buf, int len, int flags,
                     WIN::sockaddr *from, int *fromlen) {
    int res;
    PIN_CallApplicationFunction(ctxt, tid, CALLINGSTD_STDCALL, orig_funptr, NULL,
        PIN_PARG(int), &res,
        PIN_PARG(WIN::SOCKET), s,
        PIN_PARG(char *), buf,
        PIN_PARG(int), len,
        PIN_PARG(int), flags,
        PIN_PARG(WIN::sockaddr *), from,
        PIN_PARG(int *), fromlen,
        PIN_PARG_END());
    log_sockaddr(return_addr, from, WrappedCall::RECVFROM, TraceLineContent::SOCKET_EXIT, true);
    return res;
}

// https://docs.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsarecvfrom
int replace_wsarecvfrom(REPLACE_FUNCTION_COMMON_ARGS,
                        WIN::SOCKET s, WIN::LPWSABUF lpBuffers, WIN::DWORD dwBufferCount,
                        WIN::LPDWORD lpNumberOfBytesRecvd, WIN::LPDWORD lpFlags,
                        WIN::sockaddr *lpFrom, WIN::LPINT lpFromlen,
                        WIN::LPWSAOVERLAPPED lpOverlapped,
                        WIN::LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine) {
    int res;
    PIN_CallApplicationFunction(ctxt, tid, CALLINGSTD_STDCALL, orig_funptr, NULL,
        PIN_PARG(int), &res,
        PIN_PARG(WIN::SOCKET), s,
        PIN_PARG(WIN::LPWSABUF), lpBuffers,
        PIN_PARG(WIN::DWORD), dwBufferCount,
        PIN_PARG(WIN::LPDWORD), lpNumberOfBytesRecvd,
        PIN_PARG(WIN::LPDWORD), lpFlags,
        PIN_PARG(WIN::sockaddr *), lpFrom,
        PIN_PARG(WIN::LPINT), lpFromlen,
        PIN_PARG(WIN::LPWSAOVERLAPPED), lpOverlapped,
        PIN_PARG(WIN::LPWSAOVERLAPPED_COMPLETION_ROUTINE), lpCompletionRoutine,
        PIN_PARG_END());
    log_sockaddr(return_addr, lpFrom, WrappedCall::WSA_RECVFROM, TraceLineContent::SOCKET_EXIT, true);
    return res;
}

//////// sendto
PROTO proto_sendto;
PROTO proto_wsasendto;
void generate_sendto_proto() {
    proto_sendto = PROTO_Allocate(
        PIN_PARG(int), CALLINGSTD_STDCALL, "sendto",
        PIN_PARG(WIN::SOCKET), PIN_PARG(char *),
        PIN_PARG(int), PIN_PARG(int),
        PIN_PARG(WIN::sockaddr *), PIN_PARG(int),
        PIN_PARG_END()
    );
    proto_wsasendto = PROTO_Allocate(
        PIN_PARG(int), CALLINGSTD_STDCALL, "WSASendTo",
        PIN_PARG(WIN::SOCKET), PIN_PARG(WIN::LPWSABUF),
        PIN_PARG(WIN::DWORD), PIN_PARG(WIN::LPDWORD),
        PIN_PARG(WIN::DWORD), PIN_PARG(WIN::sockaddr *),
        PIN_PARG(int), PIN_PARG(WIN::LPWSAOVERLAPPED),
        PIN_PARG(WIN::LPWSAOVERLAPPED_COMPLETION_ROUTINE),
        PIN_PARG_END()
    );
}

// https://docs.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-sendto
int replace_sendto(REPLACE_FUNCTION_COMMON_ARGS,
                   WIN::SOCKET s, char *buf, int len,
                   int flags, WIN::sockaddr *to, int tolen) {
    log_sockaddr(return_addr, to, WrappedCall::SENDTO, TraceLineContent::SOCKET_ENTRY, true);
    int res;
    PIN_CallApplicationFunction(ctxt, tid, CALLINGSTD_STDCALL, orig_funptr, NULL,
        PIN_PARG(int), &res,
        PIN_PARG(WIN::SOCKET), s,
        PIN_PARG(char *), buf,
        PIN_PARG(int), len,
        PIN_PARG(int), flags,
        PIN_PARG(WIN::sockaddr *), to,
        PIN_PARG(int), tolen,
        PIN_PARG_END());
    log_sockaddr(return_addr, to, WrappedCall::SENDTO, TraceLineContent::SOCKET_EXIT, false);
    return res;
}
// https://docs.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsasendto
int replace_wsasendto(REPLACE_FUNCTION_COMMON_ARGS,
                      WIN::SOCKET s, WIN::LPWSABUF lpBuffers, WIN::DWORD dwBufferCount,
                      WIN::LPDWORD lpNumberOfBytesSent, WIN::DWORD dwFlags,
                      WIN::sockaddr *lpTo, int iTolen, WIN::LPWSAOVERLAPPED lpOverlapped,
                      WIN::LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine) {
    log_sockaddr(return_addr, lpTo, WrappedCall::WSA_SENDTO, TraceLineContent::SOCKET_ENTRY, true);
    int res;
    PIN_CallApplicationFunction(ctxt, tid, CALLINGSTD_STDCALL, orig_funptr, NULL,
        PIN_PARG(int), &res,
        PIN_PARG(WIN::SOCKET), s,
        PIN_PARG(WIN::LPWSABUF), lpBuffers,
        PIN_PARG(WIN::DWORD), dwBufferCount,
        PIN_PARG(WIN::LPDWORD), lpNumberOfBytesSent,
        PIN_PARG(WIN::DWORD), dwFlags,
        PIN_PARG(WIN::sockaddr *), lpTo,
        PIN_PARG(int), iTolen,
        PIN_PARG(WIN::LPWSAOVERLAPPED), lpOverlapped,
        PIN_PARG(WIN::LPWSAOVERLAPPED_COMPLETION_ROUTINE), lpCompletionRoutine,
        PIN_PARG_END());
    log_sockaddr(return_addr, lpTo, WrappedCall::WSA_SENDTO, TraceLineContent::SOCKET_EXIT, false);
    return res;
}

namespace hooker
{
	void setup_hooks(MessageIpc* new_message_ipc)
	{
		message_ipc = new_message_ipc;

		generate_accept_proto();
		generate_connect_proto();
		generate_recvfrom_proto();
		generate_sendto_proto();
	}

	void call_potential_hook(IMG img, SYM sym, std::string symbol_name)
	{
        bool instrumented = false;
		if (symbol_name == "accept")
		{
			REPLACE_SIGNATURE(replace_accept, proto_accept, ARGS_FUNCARG_3)
            instrumented = true;
		}
		else if (symbol_name == "WSAAccept")
		{
			REPLACE_SIGNATURE(replace_wsaaccept, proto_wsaaccept, ARGS_FUNCARG_5)
            instrumented = true;
		} 
		else if (symbol_name == "connect")
		{
			REPLACE_SIGNATURE(replace_connect, proto_connect, ARGS_FUNCARG_3)
            instrumented = true;
		}
		else if (symbol_name == "WSAConnect")
		{
			REPLACE_SIGNATURE(replace_wsaconnect, proto_wsaconnect, ARGS_FUNCARG_7)
            instrumented = true;
		}
		else if (symbol_name == "recvfrom")
		{
			REPLACE_SIGNATURE(replace_recvfrom, proto_recvfrom, ARGS_FUNCARG_6)
            instrumented = true;
		}
		else if (symbol_name == "WSARecvFrom")
		{
			REPLACE_SIGNATURE(replace_wsarecvfrom, proto_wsarecvfrom, ARGS_FUNCARG_9)
            instrumented = true;
		}
		else if (symbol_name == "sendto")
		{    
			REPLACE_SIGNATURE(replace_sendto, proto_sendto, ARGS_FUNCARG_6)
            instrumented = true;
		}
		else if (symbol_name == "WSASendTo")
		{
			REPLACE_SIGNATURE(replace_wsasendto, proto_wsasendto, ARGS_FUNCARG_9)
            instrumented = true;
		}
        if (instrumented)
        {
            global_text_logger->log("[SOCKET_WRAPPER] Wrapped " + symbol_name + '\n');
        }
	}

}

#endif