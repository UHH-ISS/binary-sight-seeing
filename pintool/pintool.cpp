#include "pin.H"
#include <iostream>
#include <fstream>
#include <vector>
#include "instruction_tracer.h"
#include "instruction_counter.h"
#include "utils/logger.h"
#include "socket_wrapper.h"
#include "message_ipc.h"

using std::cerr;
using std::string;
using std::endl;


KNOB<std::string> knob_log_file(KNOB_MODE_WRITEONCE, "pintool",
    "o", "", "The text log file name. The pid will be appended.");
KNOB<std::string> knob_trace_file(KNOB_MODE_WRITEONCE, "pintool",
    "trace", "", "The binary log file name (traces). The pid will be appended.");
KNOB<std::string> knob_ipc_file(KNOB_MODE_WRITEONCE, "pintool",
    "ipc", "", "The IPC file name. The pid will be appended.");
KNOB<std::string> knob_ins_log_file(KNOB_MODE_WRITEONCE, "pintool",
    "ins_log", "", "The instruction log file name. The pid will be appended.");

KNOB<int> knob_trace_image_filter(KNOB_MODE_WRITEONCE, "pintool", "trace_image_filter", "0", "Whether to filter the images that should be traced.");
KNOB<std::string> knob_trace_images(KNOB_MODE_APPEND, "pintool",
    "trace_image", "", "The images that should be traced. Argument needs to be passed once for every image.");
KNOB<int> knob_trace_non_image(KNOB_MODE_WRITEONCE, "pintool",
    "trace_non_image", "0", "Whether to trace instructions which aren't in any image.");
KNOB<unsigned int> knob_max_trace_count(KNOB_MODE_WRITEONCE, "pintool", "max_trace_count", "0", "The maximum number of times an instruction is traced.");
KNOB<int> knob_trace_split(KNOB_MODE_WRITEONCE, "pintool", "trace_split", "0", "The number of BBLs to trace in every trace file.");

static MessageIpc *message_ipc = nullptr;
static InstructionCounter *instruction_counter = nullptr;
static unsigned int max_ins_counter;

static int split_counter = -1;
static int bbl_counter;

// Test whether a string ends with a suffix
// Source: https://stackoverflow.com/a/20446239
bool has_suffix(const std::string &str, const std::string &suffix)
{
	return str.size() >= suffix.size() &&
		str.compare(str.size() - suffix.size(), suffix.size(), suffix) == 0;
}

string append_pid(string &name)
{
    std::ostringstream result_name;
    result_name << name.c_str() << '.';
    if (split_counter != -1)
    {
        result_name << split_counter << '.';
    }
    result_name << PIN_GetPid();
    return result_name.str();
}

void on_image_load(IMG img, void* v)
{
    global_text_logger->lock();

    if (!IMG_Valid(img)) {
        global_text_logger->log("Invalid image loaded!");
        global_text_logger->unlock();
        return;
    }
    
    std::stringstream stream;
    stream << "[MAIN] Encountered new image: " << IMG_Name(img) << std::endl;
    stream << "  | Offset: " << hexstr(IMG_LoadOffset(img), 8) << std::endl;
    global_text_logger->log(stream.str());


    // UINT id = IMG_Id(img);
    for (SYM symbol = IMG_RegsymHead(img); SYM_Valid(symbol); symbol = SYM_Next(symbol))
    {
        string und_symbol_name = PIN_UndecorateSymbolName(SYM_Name(symbol), UNDECORATION_NAME_ONLY);

        hooker::call_potential_hook(img, symbol, und_symbol_name);
    }
    global_text_logger->unlock();
}

void analysis_function_ins_counter(ADDRINT ins_addr)
{
    // Get the counter for the current function
    unsigned int current_count = instruction_counter->count(ins_addr);
    // Check that this address was counted at least once
    // and that it's above the max_ins_counter configuration.
    if (current_count > 0 && current_count > max_ins_counter) {
        // Remove instrumentation on this address.
        // This causes reinstrumentation of some code.
        PIN_RemoveInstrumentationInRange(ins_addr, ins_addr);
    }
}
void analysis_function_bbl_binary_splitter(int split_limit)
{
    PIN_MutexLock(&trace_mutex);
    bbl_counter--;
    if (bbl_counter == 0) {
        split_counter++;
        bbl_counter = split_limit;
        delete global_binary_logger;
        string file_name = knob_trace_file.Value();
        global_binary_logger = new FileLogger(append_pid(file_name));
    }
    PIN_MutexUnlock(&trace_mutex);
}

void on_trace(TRACE trace, void *split_limit)
{
    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
    {
        BBL_InsertCall(bbl, IPOINT_BEFORE,
            (AFUNPTR) analysis_function_bbl_binary_splitter,
            IARG_UINT32, (int) split_limit, IARG_END);
    }
}

void on_instruction(INS ins, void* v)
{
    if (!INS_Valid(ins))
    {
        return;
    }
    
    ADDRINT address = INS_Address(ins);
    OPCODE opcode = INS_Opcode(ins);

    // Check if the maximum instruction trace counter for this address and opcode
    // is already hit. This is the case when reinstrumenting an address
    // that was uninstrumented because the limit was hit.
    std::pair<unsigned int, OPCODE> ins_count = instruction_counter->get(address);
    if (max_ins_counter > 0 && ins_count.second == opcode && ins_count.first > max_ins_counter)
    {
        return;
    }

    
    IMG img = IMG_FindByAddress(address);
    bool img_valid = IMG_Valid(img);
    if (!img_valid && !knob_trace_non_image.Value())
    {
        return;
    }

    if (img_valid && knob_trace_image_filter.Value())
    {
        std::string image_name = IMG_Name(img);
        bool matches = false;
        for(int i = knob_trace_images.NumberOfValues()-1; i >= 0; i--)
        {
            if (has_suffix(image_name, knob_trace_images.Value(i)))
            {
                matches = true;
                break;
            }
        }
        if (!matches) return;
    }

    instruction_counter->register_instruction(address, opcode);
    
    if (max_ins_counter > 0)
    {
        INS_InsertCall(
            ins, IPOINT_BEFORE, (AFUNPTR) analysis_function_ins_counter,
            IARG_INST_PTR, IARG_END
        );
    }

    instruction_tracer::instrument_memory_read(ins, v);
    instruction_tracer::instrument_memory_write(ins, v);
    instruction_tracer::instrument_register(ins, v);

    std::ostringstream oss;
    oss << address << ';' << opcode << ';';
    oss << INS_Mnemonic(ins) << ';' << INS_Disassemble(ins) << ';';
    if (img_valid)
    {
        oss << IMG_Name(img);
    }
    oss << std::endl;
    global_ins_logger->log(oss.str());
}

int print_usage()
{
    std::cerr << KNOB_BASE::StringKnobSummary() << std::endl;
    return -1;
}

int main(int argc, char *argv[])
{
    PIN_InitSymbols();

    if (PIN_Init(argc, argv)) print_usage();
    
    std::ostringstream config_log;
    config_log << "[MAIN] Config:" << std::endl;
    string file_name = knob_log_file.Value();
    if (!file_name.empty()) 
    {
        global_text_logger = new FileLogger(append_pid(file_name));
    }
    else
    {
        global_text_logger = new NullLogger();
    }

    PIN_MutexInit(&trace_mutex);

    file_name = knob_ins_log_file.Value();
    if (!file_name.empty())
    {
        global_ins_logger = new FileLogger(append_pid(file_name));
        config_log << "[MAIN] - Instruction log file: " << append_pid(file_name) << std::endl;
    }
    else
    {
        global_ins_logger = new NullLogger();
    }

    file_name = knob_ipc_file.Value();
    if (!file_name.empty())
    {
        string path = append_pid(file_name);
        message_ipc = new MessageIpc(path);
        config_log << "[MAIN] - Message IPC file: " << append_pid(file_name) << std::endl;
    }

    bbl_counter = knob_trace_split.Value();
    if (bbl_counter != 0)
    {
        split_counter = 0;
    }
    config_log << "[MAIN] - Trace split: " << bbl_counter << std::endl;
    file_name = knob_trace_file.Value();
    if (!file_name.empty())
    {
        global_binary_logger = new FileLogger(append_pid(file_name));
        config_log << "[MAIN] - Trace file: " << append_pid(file_name) << std::endl;
    }
    else
    {
        global_binary_logger = new NullLogger();
    }

    config_log << "[MAIN] - Filter traced images: " << knob_trace_image_filter.Value() << std::endl;
    config_log << "[MAIN] - Trace images:\n";
    for (int i = knob_trace_images.NumberOfValues()-1; i >= 0; i--)
    {
        config_log << "[MAIN]   - \"" << knob_trace_images.Value(i) << "\"\n";
    }
    config_log << "[MAIN] - Trace non-image instructions: " << knob_trace_non_image.Value() << std::endl;

    instruction_counter = new InstructionCounter();
    max_ins_counter = knob_max_trace_count.Value();
    config_log << "[MAIN] - Max. instruction trace count: " << max_ins_counter << std::endl;
    global_text_logger->safe_log(config_log.str());

    hooker::setup_hooks(message_ipc);

    if (bbl_counter != 0)
    {
        TRACE_AddInstrumentFunction(on_trace, (void *) bbl_counter);
    }
    INS_AddInstrumentFunction(on_instruction, 0);
#ifdef _WIN32
    // Not needed for Linux...
    IMG_AddInstrumentFunction(on_image_load, 0);
#endif


    PIN_StartProgram();
    
    return 0;
}