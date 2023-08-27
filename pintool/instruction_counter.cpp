#include "instruction_counter.h"

#include "pin.H"

InstructionCounter::InstructionCounter() {
    PIN_MutexInit(&map_mutex_);
}

void InstructionCounter::register_instruction(ADDRINT address, OPCODE opcode) {
    PIN_MutexLock(&map_mutex_);
    
    std::pair<unsigned int, OPCODE> new_val
        = std::make_pair(0, opcode);
    std::pair<std::map<ADDRINT, std::pair<unsigned int, OPCODE>>::iterator, bool> res
        = counter_map_.insert(std::make_pair(address, new_val));
    if (!res.second) { // no insertion took place
        (*res.first).second = new_val;
    }
    PIN_MutexUnlock(&map_mutex_);
}

unsigned int InstructionCounter::count(ADDRINT address) {
    PIN_MutexLock(&map_mutex_);
    auto find_result = counter_map_.find(address);
    unsigned int counter_value;
    if (find_result != counter_map_.end()) {
        find_result->second.first++;
        counter_value = find_result->second.first;
    } else {
        counter_value = 0;
    }
    PIN_MutexUnlock(&map_mutex_);

    return counter_value;
}

std::pair<unsigned int, OPCODE> InstructionCounter::get(ADDRINT address) {
    PIN_MutexLock(&map_mutex_);
    auto find_result = counter_map_.find(address);
    std::pair<unsigned int, OPCODE> ret;
    if (find_result != counter_map_.end()) {
        ret = find_result->second;
    } else {
        ret = std::make_pair(0, (OPCODE) 0);
    }
    PIN_MutexUnlock(&map_mutex_);

    return ret;
}