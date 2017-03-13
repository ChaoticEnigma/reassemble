#ifndef CODEBLOCK_H
#define CODEBLOCK_H

#include "capstone/include/capstone/capstone.h"

#include "zstring.h"
#include "zarray.h"
using namespace LibChaos;

class CodeBlock {
public:
    enum insntype {
        NORMAL,
        BRANCH,
        LOAD,
    };

    struct Insn {
        insntype type;
        ZString prefix;
        zu64 addr;
        ZString suffix;
        zu16 size;
    };

public:
    //! New basic block at addr.
    CodeBlock(zu64 addr);

    //! Add normal instruction to block.
    bool addCode(ZString instr, zu16 size);
    //! Add branch instruction to block.
    bool addBranch(ZString prefix, zu64 jaddr, ZString suffix, zu16 size, ZArray<zu64> addrs);

    ZString toString() const;

    zu64 size() const;

private:
    zu64 addr;
    ZArray<Insn> insns;
    ZArray<zu64> next_addrs;
};

#endif // CODEBLOCK_H
