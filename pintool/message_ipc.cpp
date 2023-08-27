#include "message_ipc.h"

#include "utils/logger.h"
#include "utils/ip_address.h"

// Possible states:
// 0x00 No exchange happening
// 0x01 Pintool has sent message
// 0x02 Server has sent reply
// 0x03 Server requests resend
// 0xff MessageIpc destructed

// The structure of the memory mapped file is as follows:
// First byte: State of the client/server connection
// Remaining bytes: Contain the messages. The length of the messages
//                  need to be known by the recipients.

// The structure of the message sent by the Pintool is as follows:
// First byte: Type of the message (see below for message types)
// Remaining bytes: Payload (max 126 bytes). The structure of the 
//                  payload depends on the message type.

// There are not limits on the structure of the reply.

// Possible message types:
// 0x01: Socket Wrapper Message

#ifdef linux
char empty_buffer[IPC_BUFFER_SIZE];
#endif

MessageIpc::MessageIpc(std::string& path)
{
    PIN_MutexInit(&message_lock_);
    OS_RETURN_CODE ret = OS_OpenFD(
        path.c_str(),
        // Create file if necessary and allow read and write
        OS_FILE_OPEN_TYPE_CREATE | OS_FILE_OPEN_TYPE_WRITE | OS_FILE_OPEN_TYPE_READ,
        // When creating file set read and write
        OS_FILE_PERMISSION_TYPE_READ_OTHERS | OS_FILE_PERMISSION_TYPE_READ_GROUP | OS_FILE_PERMISSION_TYPE_READ_USER
        | OS_FILE_PERMISSION_TYPE_WRITE_OTHERS | OS_FILE_PERMISSION_TYPE_WRITE_GROUP | OS_FILE_PERMISSION_TYPE_WRITE_USER,
        &fd_
    );
    if (ret.generic_err != OS_RETURN_CODE_NO_ERROR) {
        global_text_logger->lock();
        global_text_logger->log("[MESSAGE_IPC] Unable to open file: ");
        global_text_logger->log(hexstr(ret.os_specific_err) + '\n');
        global_text_logger->unlock();
        PIN_ExitApplication(1);
    }

#ifdef linux
    USIZE bytes_written = IPC_BUFFER_SIZE;
    ret = OS_WriteFD(
        fd_,
        empty_buffer,
        &bytes_written
    );
    if (ret.generic_err != OS_RETURN_CODE_NO_ERROR) {
        global_text_logger->lock();
        global_text_logger->log("[MESSAGE_IPC] Unable to write initial data to file: ");
        global_text_logger->log(hexstr(ret.os_specific_err) + '\n');
        global_text_logger->unlock();
        PIN_ExitApplication(1);
    }
#endif

    ret = OS_MapFileToMemory(
        PIN_GetPid(),
        // Allow read and write on mapped memory region
        OS_PAGE_PROTECTION_TYPE_READ | OS_PAGE_PROTECTION_TYPE_WRITE,
        IPC_BUFFER_SIZE,
        OS_MEMORY_FLAGS_SHARED, // Allow access from multiple processes
        fd_,
        0, // Map file from the first byte
        (void**)&mmap_
    );
    if (ret.generic_err != OS_RETURN_CODE_NO_ERROR) {
        global_text_logger->lock();
        global_text_logger->log("[MESSAGE_IPC] Unable to map file to memory: ");
        global_text_logger->log(hexstr(ret.os_specific_err) + '\n');
        global_text_logger->unlock();
        PIN_ExitApplication(1);
    }
    shared_state_ = ((uint8_t*)mmap_);
    shared_buffer_ = ((uint8_t*)mmap_) + 1;

    // Set the current state to "No exchange happening"
    *shared_state_ = 0x00;
    global_text_logger->safe_log("[MESSAGE_IPC] Ready\n");
}

MessageIpc::~MessageIpc()
{
    PIN_MutexFini(&message_lock_);
    *shared_state_ = 0xff;
    OS_FreeMemory(PIN_GetPid(), (void*)mmap_, IPC_BUFFER_SIZE);
    OS_CloseFD(fd_);
}

void MessageIpc::notify_socket_call(WrappedCall call_type, uint8_t ip[4], u_short port)
{
    PIN_MutexLock(&message_lock_);
    // We can assume that the current state is 0x00
    // Copy data into mmaped region
    shared_buffer_[0] = 0x01;
    shared_buffer_[1] = (uint8_t) call_type;
    uint8_t* port_data = reinterpret_cast<uint8_t*>(&port);
    for (int i = 0; i < 4; i++)
    {
        shared_buffer_[i+2] = ip[i];
    }
    shared_buffer_[6] = port_data[1];
    shared_buffer_[7] = port_data[0];
    // Set state to "Pintool has sent message"
    *shared_state_ = 0x01;
}

void MessageIpc::await_reply()
{
    // Wait for state "Server has sent reply"
    while (*shared_state_ != 0x02) {
        if (*shared_state_ == 0x03) {
            // If the state is "Server requests resend in 1 second"
            // Wait for one second and change state to 0x01
            // This requires the server not to change the 
            // shared buffer.
            OS_Sleep(1000);
            *shared_state_ = 0x01;
        }
        else {
            // OS_Sleep(10);
        }
    }
    // Set state to "No exchange happening"
    *shared_state_ = 0x00;
    PIN_MutexUnlock(&message_lock_);
}