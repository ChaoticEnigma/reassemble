## ReAssembler

The ReAssembler is a tool for producing editable assembly code from compiled or assembled
machine instructions. Currently only Thumb2 is supported (the author's motivation).

The ideal implementation would allow a binary dump of assembled instructions and data
(e.g. ARM firmware) to be disassembled into an assembly file, which could be again assembled
into a binary format identical or functionally identical to the original. Where this differs
from a normal disassembler (e.g. objdump -D), is that code paths are followed, so that data
is not disassembled, direct branches and pc-relative loads are replaced with labels, and
other position-dependent code is transformed, such that the resulting assembly can be
substantially modified, without having to fit the memory map of the original binary.

In order to follow the code, this tool must be provided with all unique entry points,
including the reset handler, IRQs, and addresses referenced outside the code
(e.g. by a bootloader).

This tool is intended as a convenience, and cannot guarantee the output will be completely
independent of address dependence (e.g. a vector table, obscure function pointers).
The output will likely need to be verified manually.

### Features
- Instructions disassembled
- Data preserved in assembly output
- PC-relative branches replaced with labels
- PC-relative loads replaced with labels
- Function pointers in data replaced with symbols
- Data pointers in data replaced with symbols

If at this point you do not understand what this tool does, it is probably not for you.
To use this tool correctly, you need to understand the information you are providing it,
know what to expect in the output, and know how to validate the output.
