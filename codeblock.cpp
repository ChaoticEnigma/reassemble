#include "codeblock.h"
#include "zlog.h"

CodeBlock::CodeBlock(zu64 iaddr) : addr(iaddr){

}

bool CodeBlock::addCode(ZString instr, zu16 size){
    Insn insn;
    insn.type = NORMAL;
    insn.prefix = instr;
    insn.size = size;
    insns.push(insn);
    return true;
}

bool CodeBlock::addBranch(ZString prefix, zu64 jaddr, ZString suffix, zu16 size, ZArray<zu64> addrs){
    Insn insn;
    insn.type = BRANCH;
    insn.prefix = prefix;
    insn.addr = jaddr;
    insn.suffix = suffix;
    insn.size = size;
    insns.push(insn);
    // Next block addresses
    next_addrs = addrs;
    return true;
}

ZString CodeBlock::toString() const {
    ZString str;
    for(zu64 i = 0; i < insns.size(); ++i){
        Insn insn = insns[i];
        ZString istr;
        switch(insn.type){
            case NORMAL:
                istr = insn.prefix;
                break;
            case BRANCH:
            case LOAD:
                istr = insn.prefix + ZString::ItoS(insn.addr, 16) + insn.suffix;
                break;
            default:
                ELOG("Unknown instruction type");
                istr = "ERROR";
                break;
        }
        str += (istr + "\n");
    }
    return str;
}

zu64 CodeBlock::size() const {
    zu64 len = 0;
    for(zu64 i = 0; i < insns.size(); ++i)
        len += insns[i].size;
    return len;
}
