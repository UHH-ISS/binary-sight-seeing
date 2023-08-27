#pragma once
#include <string>
#include <pin.H>
#include <vector>
#include "utils/logger.h"
#include "utils/enums.h"
#include "message_ipc.h"

namespace hooker 
{
	using std::pair;
	using std::string;
	using std::vector;

	extern vector<pair<string, void(*)(RTN)>> hook_initializer; // <function_name_to_hook, function_pointer_init_hook>
	void call_potential_hook(IMG img, SYM symbol, std::string symbol_name);
	void setup_hooks(MessageIpc *new_message_ipc);
}