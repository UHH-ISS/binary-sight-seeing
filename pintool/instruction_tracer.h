#pragma once
#include "pin.H"
#include "utils/enums.h"



namespace instruction_tracer {
	static const int MEM_CHUNK_SIZE = 1024;


    void instrument_register(INS ins, void* v);
	void instrument_memory_read(INS ins, void* v);
	void instrument_memory_write(INS ins, void* v);
} 