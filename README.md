## ReAssembler

The ReAssembler is a tool for producing editable assembly code from compiled or assembled
machine instructions. Currently only Thumb2 is supported (the author's motivation).

### Features
- Instructions disassembled
- Branch and call addresses replaced with labels
- Non-code data preserved in assembly output
- PC-relative loads given labels (pc offsets remain)
- Function and data pointers replaced with labels

This tool is intended as a convenience, and cannot guarantee the output will be completely
independent of address dependence (e.g. a vector table, obscure function pointers).
The output will likely need to be verified manually.

In order to follow the code, this tool must be provided with all unique entry points,
including the reset handler, IRQs, and addresses referenced outside the code
(e.g. by a bootloader).

I will admit the current incarnation is somewhat sloppy, but effective. Function and data
pointer auto-analysis is limited. However, you can provide lists of functions, data,and
pointers to each, and the tool disassemble as necessary, add labels, and reference labels
in pointers, so address values are re-generated appropriately by the linker.

If at this point you do not understand what this tool does, it is probably not for you.
To use this tool correctly, you need to understand the information you are providing it,
know what to expect in the output, and know how to validate the output.

### Usage

    reassemble <input.bin> <output.s>
        [-a <image offset>]
        [-s <symbol address list file>]
        [-d <data address list file>]

### Example

    # Disassemble to assembly
    reassemble example/firmware_v117.bin out.s -a 2c00 -s example/symbols_v117.txt -d example/pointers_v117.txt
    # Reassemble with standard tools
    reas.sh

