#include <iostream>
#include <vector>
#include <memory>
#include <string>
#include <LIEF/LIEF.hpp>
#include <capstone/capstone.h>

#include "disassembler.h"

typedef struct
{
    std::string arch_name;
    cs_arch arch;
    cs_mode mode;
} file_arch_t;

file_arch_t get_file_arch(const std::unique_ptr<LIEF::Binary> &binary)
{
    file_arch_t file_arch = {"", CS_ARCH_ALL, CS_MODE_LITTLE_ENDIAN}; // default values

    if (binary->format() == LIEF::Binary::ELF)
    {
        const auto *elf_binary = dynamic_cast<const LIEF::ELF::Binary *>(binary.get());

        if (elf_binary)
        {
            switch (elf_binary->header().machine_type())
            {
            case LIEF::ELF::ARCH::AARCH64:
                file_arch.arch_name = "AARCH64";
                file_arch.arch = CS_ARCH_ARM64;
                file_arch.mode - CS_MODE_ARM;
                break;
            case LIEF::ELF::ARCH::X86_64:
                file_arch.arch_name = "x86_64";
                file_arch.arch = CS_ARCH_X86;
                file_arch.mode = CS_MODE_64;
                break;
            case LIEF::ELF::ARCH::I386:
                file_arch.arch_name = "I386";
                file_arch.arch = CS_ARCH_X86;
                file_arch.mode = CS_MODE_32;
                break;
            default:
                std::cerr << "Unsupported ELF architecture." << std::endl;
                break;
            }
        }
    }
    else if (binary->format() == LIEF::Binary::PE)
    {
        const auto *pe_binary = dynamic_cast<const LIEF::PE::Binary *>(binary.get());

        if (pe_binary)
        {
            switch (pe_binary->header().machine())
            {
            case LIEF::PE::Header::MACHINE_TYPES::AMD64:
                file_arch.arch_name = "x86_64";
                file_arch.arch = CS_ARCH_X86;
                file_arch.mode - CS_MODE_64;
                break;
            case LIEF::PE::Header::MACHINE_TYPES::I386:
                file_arch.arch_name = "I386";
                file_arch.arch = CS_ARCH_X86;
                file_arch.mode = CS_MODE_32;
                break;
            default:
                std::cerr << "Unsupported PE architecture." << std::endl;
                break;
            }
        }
    }
    else if (binary->format() == LIEF::Binary::MACHO)
    {
        const auto *macho_binary = dynamic_cast<const LIEF::MachO::Binary *>(binary.get());

        if (macho_binary)
        {
            switch (macho_binary->header().cpu_type())
            {
            case LIEF::MachO::Header::CPU_TYPE::ARM64:
                file_arch.arch_name = "AARCH64";
                file_arch.arch = CS_ARCH_ARM64;
                file_arch.mode = CS_MODE_ARM;
                break;
            case LIEF::MachO::Header::CPU_TYPE::X86_64:
                file_arch.arch_name = "x86_64";
                file_arch.arch = CS_ARCH_X86;
                file_arch.mode = CS_MODE_64;
            default:
                std::cerr << "Unsupported MachO architecture." << std::endl;
                break;
            }
        }
    }
    else
    {
        std::cerr << "Unsupported binary format." << std::endl;
    }

    return file_arch;
}

void disassemble_code(const std::vector<uint8_t> &code, uint64_t address, file_arch_t file_arch)
{
    if (file_arch.arch == CS_ARCH_ALL && file_arch.mode == CS_MODE_LITTLE_ENDIAN)
    {
        return;
    }

    csh handle;
    cs_insn *insn;

    // Initialize Capstone engine
    if (cs_open(file_arch.arch, file_arch.mode, &handle) != CS_ERR_OK)
    {
        std::cerr << "Capstone initialization error." << std::endl;
        return;
    }

    // Perform disassembly
    size_t count = cs_disasm(handle, code.data(), code.size(), address, 0, &insn);
    if (count > 0)
    {
        for (size_t i = 0; i < count; ++i)
        {
            // Print instruction address, mnemonic, and operands
            std::cout << "0x" << std::hex << insn[i].address << ": " << insn[i].mnemonic << " " << insn[i].op_str << std::endl;
        }
        cs_free(insn, count); // Free allocated instructions
    }
    else
    {
        std::cerr << "Disassembly error." << std::endl;
    }

    cs_close(&handle); // Close Capstone engine
}

int disassembler(const std::string &filename)
{
    // Parse the executable file using LIEF
    std::unique_ptr<LIEF::Binary> binary;
    try
    {
        binary = LIEF::Parser::parse(filename);
    }
    catch (const std::exception &e)
    {
        std::cerr << "Error while parsing the file: " << e.what() << std::endl;
        exit(EXIT_FAILURE);
    }

    if (!binary)
    {
        std::cerr << "Unable to analyze the file" << std::endl;
        exit(EXIT_FAILURE);
    }

    std::cout << "File format detected: " << LIEF::to_string(binary->format()) << std::endl;

    // Find the .text section
    const LIEF::Section *text_section = nullptr;
    for (const LIEF::Section &section : binary->sections())
    {
        if (section.name() == ".text")
        {
            text_section = &section;
            break;
        }
    }

    if (!text_section)
    {
        std::cerr << ".text section not found in the file." << std::endl;
        exit(EXIT_FAILURE);
    }

    // Retrieve the machine code from the .text section
    const auto &code_span = text_section->content();

    // Convert the span to a vector
    std::vector<uint8_t> code(code_span.begin(), code_span.end());
    uint64_t code_address = text_section->virtual_address();

    file_arch_t file_arch = get_file_arch(binary);

    std::cout << "Architecture: " << file_arch.arch_name << std::endl;

    std::cout << "'.text' section found: Size = " << code.size() << ", Address = 0x" << std::hex << code_address << std::endl;

    // Disassemble the code
    disassemble_code(code, code_address, file_arch);

    return 0;
}
