#pragma once

#include "pin.H"
#include <string>
#include <vector>

#include "utils/enums.h"

#define IPC_BUFFER_SIZE 1024

class MessageIpc {
public:
    MessageIpc(std::string& path);
    ~MessageIpc();

    void notify_socket_call(WrappedCall callType, uint8_t ip[4], u_short port);
    void await_reply();
private:
    NATIVE_FD fd_;
    volatile void* mmap_;
    volatile uint8_t* shared_state_;
    volatile uint8_t* shared_buffer_;
    PIN_MUTEX message_lock_;
};