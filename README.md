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
pointer auto-analysis is limited. However, you can provide lists of functions, data, and
code/data pointers, with custom lables, and the tool will disassemble as necessary,
add labels, and reference labels in pointers, so address values are re-generated
appropriately by the linker. See the examples directory for sample symbol/pointer lists.

If at this point you do not understand what this tool does, it is probably not for you.
To use this tool correctly, you need to understand the information you are providing it,
know what to expect in the output, and know how to validate the output.

### Usage

    reassemble input_binary output_asm
        [-V] [-E] [-a image_vma]
        [-s symbol_address_file]
        [-d data_address_file]

### Example

    # Disassemble to assembly
    reassemble example/firmware.bin out.s -a 2c00 -s example/symbols.sym -d example/data.sym
    # Reassemble with standard tools, compare output and source binaries
    reas.sh out.s example/firmware_v117
    
### Symbol Address File
example/symbols.sym

    # Function function1 at 0x2c04
    2c04: function1
    # Address of function2 at 0x2d08
    * 2d08: function2
    # Automatically name function at 0x3a00
    0x3a00
    
    # Define the number of cases in switch instruction at 2ddc as 12
    & 2ddc: 12
    
### Data Address File
example/data.sym

    # Data data1 at 0x2c04
    2c04: data1
    # Address of data2 at 0x2d08
    * 2d08: data2
