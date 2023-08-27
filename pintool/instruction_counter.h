#pragma once

#include "pin.H"
#include <map>
#include <utility>

/* A counter that counts how often an instruction
at a specific memory address is executed.
It uses a PIN_MUTEX to synchronize access to the values.
It also stores the OPCODE for every memory address to identify
SMC (self modifying code). */
class InstructionCounter {
private:
	PIN_MUTEX map_mutex_;
	std::map<ADDRINT, std::pair<unsigned int, OPCODE>> counter_map_;

public:
	InstructionCounter();
	void register_instruction(ADDRINT address, OPCODE opcode);
	unsigned int count(ADDRINT address);
    std::pair<unsigned int, OPCODE> get(ADDRINT address);
};