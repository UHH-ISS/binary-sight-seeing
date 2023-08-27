#include "instruction_tracer.h"
#include "utils/logger.h"
#include <sstream>

using instruction_tracer::MEM_CHUNK_SIZE;

// TODO thread safe if mt is needed
char register_log[1 + 4 + 6 * 4]; // ins_addr, type, eax, ebx, ecx, edx, esi, edi
void analyse_register(ADDRINT ins_addr, THREADID tid,
    ADDRINT eax, ADDRINT ebx,
    ADDRINT ecx, ADDRINT edx,
    ADDRINT esi, ADDRINT edi, bool tagged)
{
    PIN_MutexLock(&trace_mutex);
    register_log[0] = (uint8_t)TraceLineContent::REGS;
    *((ADDRINT*)&register_log[1]) = ins_addr;
    *((ADDRINT*)&register_log[5]) = eax;
    *((ADDRINT*)&register_log[9]) = ebx;
    *((ADDRINT*)&register_log[13]) = ecx;
    *((ADDRINT*)&register_log[17]) = edx;
    *((ADDRINT*)&register_log[21]) = esi;
    *((ADDRINT*)&register_log[25]) = edi;
    
    std::string str(register_log, 1 + 4 + 6 * 4);
    global_binary_logger->log("\xA1\xA2\xA3\xA4" + str);
  
    PIN_MutexUnlock(&trace_mutex);
}

// TODO change to local if mt
// TODO, check max memory that can be accessed by one instruction
char memory_log[1 + 4 + 4 + 4 + MEM_CHUNK_SIZE]; // type, ins_addr, mem_addr, size, content_buffer

int read_memory_content(void* ea, int size) 
{
    ssize_t read_bytes = PIN_SafeCopy(&memory_log[1+4+4+4], ea, size);

    if (read_bytes != size) 
    {
        global_text_logger->lazy_log("Readbytes and size does not match");
    }

    return read_bytes;
}


void analyse_memory(void* ip, bool read, void* addr, uint size, bool prefetch) 
{
    memory_log[0] = MEM_W;

    if (read) // Client is already locked if write!
    {
        memory_log[0] = MEM_R;
        PIN_MutexLock(&trace_mutex);
    }

    memcpy(&memory_log[1], &ip, 4); // instruction_address
    memcpy(&memory_log[5], &addr, 4); // memory_address

    if (size > 1024) // TODO handling of this? 
    {
        return;
    }

    int read_bytes = read_memory_content(addr, size);     // TODO is this realy neccessary for writes AND reads? Just writes maybe..?
    memcpy(&memory_log[9], &read_bytes, 4); // read / write size
    std::string memory_log_entry(memory_log, 1 + 4 + 4 + 4 + read_bytes);

    global_binary_logger->log("\xA1\xA2\xA3\xA4" + memory_log_entry);
    PIN_MutexUnlock(&trace_mutex);
}

// Globals / TODO TLS IF locking on_instruction makes the program to slow
void* write_addr;
int write_size;

void save_mem_write_info(void* addr, int size)
{
    PIN_MutexLock(&trace_mutex);
    write_addr = addr;
    write_size = size;
}

void analyse_memory_write(void* ip)
{
    analyse_memory(ip, false, write_addr, write_size, false);
}

void instruction_tracer::instrument_register(INS ins, void* v)
{
    INS_InsertCall(
        ins, IPOINT_BEFORE, (AFUNPTR)analyse_register,
        IARG_CALL_ORDER, CALL_ORDER_FIRST,
        IARG_INST_PTR,
        IARG_THREAD_ID,
        IARG_REG_VALUE, REG_EAX,
        IARG_REG_VALUE, REG_EBX,
        IARG_REG_VALUE, REG_ECX,
        IARG_REG_VALUE, REG_EDX,
        IARG_REG_VALUE, REG_ESI,
        IARG_REG_VALUE, REG_EDI,
        IARG_END
    );
}

void instruction_tracer::instrument_memory_read(INS ins, void* v)
{
    if (INS_IsMemoryRead(ins) && INS_IsStandardMemop(ins))
    {
        INS_InsertPredicatedCall(
            ins, IPOINT_BEFORE, (AFUNPTR)analyse_memory,
            IARG_INST_PTR,
            IARG_BOOL, true,
            IARG_MEMORYREAD_EA,
            IARG_MEMORYREAD_SIZE,
            IARG_BOOL, INS_IsPrefetch(ins),
            IARG_END);
    }

    if (INS_HasMemoryRead2(ins) && INS_IsStandardMemop(ins))
    {
        INS_InsertPredicatedCall(
            ins, IPOINT_BEFORE, (AFUNPTR)analyse_memory,
            IARG_INST_PTR,
            IARG_BOOL, true,
            IARG_MEMORYREAD2_EA,
            IARG_MEMORYREAD_SIZE,
            IARG_BOOL, INS_IsPrefetch(ins),
            IARG_END);
    }
}

void instruction_tracer::instrument_memory_write(INS ins, void* v)
{
    if ((INS_IsMemoryWrite(ins) && INS_IsStandardMemop(ins))
        && (INS_IsValidForIpointAfter(ins) || INS_IsValidForIpointTakenBranch(ins)))
    {
        INS_InsertPredicatedCall(
            ins, IPOINT_BEFORE, (AFUNPTR)save_mem_write_info,
            IARG_MEMORYWRITE_EA,
            IARG_MEMORYWRITE_SIZE,
            IARG_END);

        if (INS_IsValidForIpointAfter(ins))
        {
            INS_InsertCall(
                ins, IPOINT_AFTER, (AFUNPTR)analyse_memory_write,
                IARG_INST_PTR,
                IARG_END);
        }
        else
        {
            INS_InsertCall(
                ins, IPOINT_TAKEN_BRANCH, (AFUNPTR)analyse_memory_write,
                IARG_INST_PTR,
                IARG_END);
        }
    }
}