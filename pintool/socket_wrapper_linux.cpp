// TODO: REMOVE?

#include "socket_wrapper.h"

#ifdef linux

#include "sys/socketcalls.h"
#include "utils/sockaddr.h"

#define PADSIZE 64 - 2*sizeof(ADDRINT) - sizeof(sockaddr *) - sizeof(ADDRINT *)

MessageIpc *message_ipc;
static TLS_KEY tls_key = INVALID_TLS_KEY;

struct thread_data_t {
public:
    ADDRINT syscall_number;
    ADDRINT socket_call;
    sockaddr *addr;
    ADDRINT *args;
    UINT8 _pat[PADSIZE];
};

thread_data_t *get_tls(THREADID tid)
{
    thread_data_t* tdata = static_cast<thread_data_t*>(PIN_GetThreadData(tls_key, tid));
    if (tdata == NULL)
    {
        global_text_logger->safe_log("[SOCKET_WRAPPER] Unable to get TLS\n");
        PIN_ExitApplication(1);
    }
    return tdata;
}

void log_sockaddr(ADDRINT return_addr, sockaddr* sockaddr, WrappedCall wrapped_call, TraceLineContent tlc, bool send_ipc)
{
    if (sockaddr == NULL) return;
    if (sockaddr->sa_family != AF_INET) return;
    PIN_LockClient();
    PIN_MutexLock(&trace_mutex);
    sockaddr_in* sockaddr_in = reinterpret_cast<struct sockaddr_in*>(sockaddr);
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
// https://man7.org/linux/man-pages/man2/accept.2.html
void before_accept(thread_data_t *tdata, CONTEXT *ctxt, SYSCALL_STANDARD std) {

}

#define LOG_INDEX(addr_index, wrapped_call, trace_line_content, send_ipc) \
log_sockaddr( \
    PIN_GetContextReg(ctxt, REG_INST_PTR), \
    (sockaddr *) tdata->args[addr_index], \
    wrapped_call, trace_line_content, send_ipc \
)

#define LOG_STORED(wrapped_call, trace_line_content, send_ipc) \
log_sockaddr( \
    PIN_GetContextReg(ctxt, REG_INST_PTR), \
    tdata->addr, wrapped_call, trace_line_content, send_ipc \
)

#define STORE_ADDR(addr_index) \
tdata->addr = (sockaddr *) tdata->args[addr_index];

void on_syscall_entry(THREADID tid, CONTEXT *ctxt, SYSCALL_STANDARD std, void *v)
{
    ADDRINT syscall_number = PIN_GetSyscallNumber(ctxt, std);
    if (syscall_number != 102) return;

    thread_data_t *tdata = get_tls(tid);
    tdata->syscall_number = syscall_number;
    tdata->socket_call = PIN_GetSyscallArgument(ctxt, std, 0);
    tdata->args = (ADDRINT *) PIN_GetSyscallArgument(ctxt, std, 1);

    std::ostringstream oss;
    oss << "Syscall: " << tdata->syscall_number << "\n";
    oss << "Socketcall: " << tdata->socket_call << "\n";
    global_text_logger->safe_log(oss.str());

    switch (tdata->socket_call)
    {
    // https://man7.org/linux/man-pages/man2/accept.2.html
    case SYS_ACCEPT:
    case SYS_ACCEPT4:
        STORE_ADDR(1);
        break;
    // https://man7.org/linux/man-pages/man2/connect.2.html
    case SYS_CONNECT:
        STORE_ADDR(1);
        LOG_INDEX(1, WrappedCall::CONNECT, TraceLineContent::SOCKET_ENTRY, true);
        break;
    // https://man7.org/linux/man-pages/man2/send.2.html
    case SYS_SENDTO:
        STORE_ADDR(4);
        LOG_INDEX(4, WrappedCall::SENDTO, TraceLineContent::SOCKET_ENTRY, true);
        break;
    case SYS_SENDMSG:
        {
            struct msghdr *msg = (struct msghdr *) tdata->args[1];
            log_sockaddr(
                PIN_GetContextReg(ctxt, REG_INST_PTR),
                (sockaddr *) msg->msg_name,
                WrappedCall::SENDTO,
                TraceLineContent::SOCKET_ENTRY,
                true
            );
            tdata->addr = (sockaddr *) msg->msg_name;
            break;
        }
    // https://man7.org/linux/man-pages/man2/sendmmsg.2.html
    case SYS_SENDMMSG:
        {
            struct mmsghdr *mmsg = (struct mmsghdr *) tdata->args[1];
            log_sockaddr(
                PIN_GetContextReg(ctxt, REG_INST_PTR),
                (sockaddr *) mmsg->msg_hdr.msg_name,
                WrappedCall::SENDTO,
                TraceLineContent::SOCKET_ENTRY,
                true
            );
            tdata->addr = (sockaddr *) mmsg->msg_hdr.msg_name;
            break;
        }
    default:
        break;
    }
}

void on_syscall_exit(THREADID tid, CONTEXT *ctxt, SYSCALL_STANDARD std, void *v)
{
    thread_data_t *tdata = get_tls(tid);
    if (tdata->syscall_number != 102) return;

    switch (tdata->socket_call)
    {
    // https://man7.org/linux/man-pages/man2/accept.2.html
    case SYS_ACCEPT:
    case SYS_ACCEPT4:
        STORE_ADDR(1);
        LOG_STORED(WrappedCall::ACCEPT, TraceLineContent::SOCKET_EXIT, true);
        break;
    // https://man7.org/linux/man-pages/man2/connect.2.html
    case SYS_CONNECT:
        LOG_STORED(WrappedCall::CONNECT, TraceLineContent::SOCKET_EXIT, false);
        break;
    // https://man7.org/linux/man-pages/man2/recv.2.html
    case SYS_RECVFROM:
        LOG_INDEX(4, WrappedCall::RECVFROM, TraceLineContent::SOCKET_EXIT, true);
        break;
    case SYS_RECVMSG:
        {
            struct msghdr *msg = (struct msghdr *) tdata->args[1];
            log_sockaddr(
                PIN_GetContextReg(ctxt, REG_INST_PTR),
                (sockaddr *) msg->msg_name,
                WrappedCall::RECVFROM,
                TraceLineContent::SOCKET_EXIT,
                true
            );
            break;
        }
    // https://man7.org/linux/man-pages/man2/recvmmsg.2.html
    case SYS_RECVMMSG:
        {
            struct mmsghdr *mmsg = (struct mmsghdr *) tdata->args[1];
            log_sockaddr(
                PIN_GetContextReg(ctxt, REG_INST_PTR),
                (sockaddr *) mmsg->msg_hdr.msg_name,
                WrappedCall::RECVFROM,
                TraceLineContent::SOCKET_EXIT,
                true
            );
            break;
        }
    // https://man7.org/linux/man-pages/man2/send.2.html
    // https://man7.org/linux/man-pages/man2/sendmmsg.2.html
    case SYS_SENDTO:
    case SYS_SENDMSG:
    case SYS_SENDMMSG:
        LOG_STORED(WrappedCall::SENDTO, TraceLineContent::SOCKET_EXIT, false);
        break;
    default:
        break;
    }

    tdata->syscall_number = 0;
    tdata->socket_call = 0;
    tdata->addr = NULL;
    tdata->args = NULL;
}

void on_thread_start(THREADID tid, CONTEXT *ctxt, INT32 flags, void *v)
{
    thread_data_t *tdata = new thread_data_t;
    tdata->syscall_number = 0;
    tdata->socket_call = 0;
    tdata->addr = NULL;
    tdata->args = NULL;
    if (PIN_SetThreadData(tls_key, tdata, tid) == FALSE)
    {
        global_text_logger->safe_log("[SOCKET_WRAPPER] Unable to set thread data\n");
        PIN_ExitApplication(1);
    }
}

void on_thread_fini(THREADID tid, const CONTEXT *ctxt, INT32 code, void *v)
{
    thread_data_t *tdata = get_tls(tid);
    delete tdata;
}

namespace hooker
{
    void setup_hooks(MessageIpc* new_message_ipc)
    {
        message_ipc = new_message_ipc;
        tls_key = PIN_CreateThreadDataKey(NULL);
        if (tls_key == INVALID_TLS_KEY)
        {
            global_text_logger->log("[SOCKET_WRAPPER] Unable to create TLS key\n");
            PIN_ExitApplication(1);
        }

        PIN_AddThreadStartFunction(on_thread_start, NULL);
        PIN_AddThreadFiniFunction(on_thread_fini, NULL);
        PIN_AddSyscallEntryFunction(on_syscall_entry, NULL);
        PIN_AddSyscallExitFunction(on_syscall_exit, NULL);
    }

    void call_potential_hook(IMG img, SYM sym, std::string symbol_name)
    {
        // We ignore this as for linux we instrument syscalls
    }
} // namespace hooker


#endif