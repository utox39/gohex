#include <cstring>

#include "disassembler.h"
#include "disassembler_wrapper.h"

int disassembler_wrapper(const char *filename)
{
    std::string cpp_output;

    int exit_status = disassembler(std::string(filename));

    return exit_status;
}