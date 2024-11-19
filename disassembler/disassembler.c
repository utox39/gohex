// disassembler.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <capstone/capstone.h>
#include <libelf.h>
#include <gelf.h>

#include "disassembler.h"

#define TEMP_BUFFER_SIZE 256

void append_formatted(char **output, const char *format, ...) {
    char temp[TEMP_BUFFER_SIZE]; // Temporary buffer
    va_list args;

    // Prepare the formatted string
    va_start(args, format);
    vsnprintf(temp, sizeof(temp), format, args);
    va_end(args);

    // Resize `output` and add the contents of `temp`
    size_t new_size = strlen(*output) + strlen(temp) + 1;
    *output = realloc(*output, new_size);
    if (*output == NULL) {
        fprintf(stderr, "Memory allocation error for output buffer.\n");
        exit(EXIT_FAILURE);
    }
    strcat(*output, temp);
}

void disassemble_code(const uint8_t* code, size_t size, uint64_t address, char** output) {
    csh handle;
    cs_insn *insn;
    size_t count;

    // Temporary buffer to add data
    char temp[TEMP_BUFFER_SIZE];

    // Initializing the disassembler
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
        append_formatted(output, "Capstone initialization error.\n","");
        return;
    }

    // Disassembly
    count = cs_disasm(handle, code, size, address, 0, &insn);
    if (count > 0) {
        for (size_t i = 0; i < count; i++) {
            append_formatted(output, "0x%" PRIx64 ": %s %s\n", insn[i].address, insn[i].mnemonic, insn[i].op_str);
        }
        cs_free(insn, count);
    } else {
        cs_close(&handle);
        append_formatted(output, "Error in the disassembly.\n", "");
        return;
    }

    // Close the disassembler
    cs_close(&handle);
}

void process_elf(const char *filename, char** output) {
    char temp[TEMP_BUFFER_SIZE];

    if (elf_version(EV_CURRENT) == EV_NONE) {
        append_formatted(output, "ELF library initialization error.\n");
        return;
    }

    FILE *file = fopen(filename, "rb");
    if (!file) {
        append_formatted(output, "Error opening file.\n");
        return;
    }

    Elf *elf = elf_begin(fileno(file), ELF_C_READ, NULL);
    if (!elf) {
        append_formatted(output, "Error reading the ELF file: %s\n", elf_errmsg(-1));
        fclose(file);
        return;
    }

    GElf_Ehdr ehdr;
    if (!gelf_getehdr(elf, &ehdr)) {
        append_formatted(output, "Error reading the ELF header: %s\n", elf_errmsg(-1));
        elf_end(elf);
        fclose(file);
        return;
    }

    // Iterates through the sections
    size_t shstrndx;
    if (elf_getshdrstrndx(elf, &shstrndx) != 0) {
        append_formatted(output, "Error in reading section string indexes: %s\n", elf_errmsg(-1));
        elf_end(elf);
        fclose(file);
        return;
    }

    Elf_Scn *scn = NULL;
    while ((scn = elf_nextscn(elf, scn)) != NULL) {
        GElf_Shdr shdr;
        if (!gelf_getshdr(scn, &shdr)) {
            append_formatted(output, "Error reading section header: %s\n", elf_errmsg(-1));
            continue;
        }

        char *section_name = elf_strptr(elf, shstrndx, shdr.sh_name);
        if (!section_name) {
            append_formatted(output, "Error in reading the section name: %s\n", elf_errmsg(-1));
            continue;
        }

        // Identifies sections containing executable code
        if ((shdr.sh_flags & SHF_EXECINSTR) && shdr.sh_size > 0) {
            append_formatted(output, "\nDisassembly of section: %s\n", section_name);

            append_formatted(output, "Virtual Address: 0x%" PRIx64 "\n", (uint64_t)shdr.sh_addr);

            append_formatted(output, "Size: %zu byte\n\n", (size_t)shdr.sh_size);

            // Reads section data
            Elf_Data *data = elf_getdata(scn, NULL);
            if (!data) {
                append_formatted(output, "Error in reading section data: %s\n", elf_errmsg(-1));
                continue;
            }

            // Code disassembly
            disassemble_code((const uint8_t *)data->d_buf, data->d_size, shdr.sh_addr, output);
        }
    }

    elf_end(elf);
    fclose(file);
}

void disassemble(const char *filename, char** output) {
    char* output_buffer = (char*)malloc(sizeof(char) * 1);
    if (output_buffer == NULL) {
        fprintf(stderr, "Memory allocation error for the output buffer.\n");
        exit(EXIT_FAILURE);
    }
    output_buffer[0] = '\0';

    process_elf(filename, &output_buffer);

    *output = realloc(*output, strlen(output_buffer) + 1);
    strncpy(*output, output_buffer, strlen(output_buffer));

    free(output_buffer);
}
