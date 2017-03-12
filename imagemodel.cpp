#include "imagemodel.h"
#include "zlog.h"

#include "capstone/include/capstone.h"

ImageModel::ImageModel() : base(0){
    err = cs_open(CS_ARCH_ARM, CS_MODE_THUMB, &handle);
    if(err != CS_ERR_OK){
        ELOG("failed to open capstone");
        return;
    }
    err = cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    if(err != CS_ERR_OK){
        ELOG("failed to set capstone option");
        return;
    }
}

ImageModel::~ImageModel(){
    cs_close(&handle);
}

void ImageModel::loadImage(const ZBinary &inbin, zu64 offset){
    base = offset;
    image = inbin;
}

zu64 ImageModel::addEntry(zu64 addr, ZString name){
    addLabel(addr, CODE, NAMED, name);
    return disassembleAddress(addr);
}

zu64 ImageModel::addCodePointer(zu64 addr, ZString name){
    zu64 offset = _addrToOffset(addr);

    if(code.contains(addr)){
        ELOG("pointer is code");
        return 0;
    }

    image.seek(offset);
    zu64 taddr = image.readleu32() & ~(zu64)1;

    if(base > taddr){
        ELOG("pointer in wrong range");
        return 0;
    }
    zu64 toffset = taddr - base;
    if(toffset >= image.size()){
        ELOG("pointer out of bounds " << HEX(addr) << " " << HEX(taddr));
        return 0;
    }

    DataWord dword;
    dword.type = CPTR;
    dword.data = taddr;
    data.add(addr, dword);

    addLabel(taddr, CODE, NAMED, name, true);
    return disassembleAddress(taddr);
}

zu64 ImageModel::addData(zu64 addr, ZString name){
    addLabel(addr, DATA, NAMED, name);
    return 0;
}

zu64 ImageModel::addDataPointer(zu64 addr, ZString name){
    zu64 offset = _addrToOffset(addr);

    if(code.contains(addr)){
        ELOG("pointer is code");
        return 0;
    }

    image.seek(offset);
    zu64 taddr = image.readleu32();

    if(base > taddr){
        ELOG("pointer in wrong range");
        return 0;
    }
    zu64 toffset = taddr - base;
    if(toffset > image.size()){
        ELOG("pointer out of bounds " << HEX(addr) << " " << HEX(taddr));
        return 0;
    }

    DataWord dword;
    dword.type = DPTR;
    dword.data = taddr;
    data.add(addr, dword);

    return addData(taddr, name);
}

zu64 ImageModel::disassembleAddress(zu64 addr){
    zu64 offset = _addrToOffset(addr);

    // if this address is already disassembled we're done
    if(insns.contains(addr)){
        return 0;
    }
//    LOG("Disassemble from 0x" << HEX(addr) << " (" << label.str << ")");

    const zu8 *iptr = image.raw() + offset;
    zu64 isize = image.size() - offset;
    zu64 iaddr = base + offset;
    cs_insn *insn = cs_malloc(handle);
    zu64 total = 0;

    // vars for indirect jumps
    unsigned ldr_reg = ARM_REG_INVALID;
    zu64 ldr_addr = 0;
    zu64 ldr_data = 0;
    bool ldr_flag = false;

    bool stop = false;

    ZPointer<CodeBlock> block = new CodeBlock(addr);
    code.add(addr, block);

    while(true){
        // disassemble instructions
        if(cs_disasm_iter(handle, &iptr, &isize, &iaddr, insn)){

            if(insns.contains(iaddr)){
                // ran into already disassembled code
                cs_free(insn, 1);
                return total;
            }

            CodeBlock::Insn cins;
            cins.type = CodeBlock::NORMAL;
            cins.prefix = ZString(insn->mnemonic) + " " + insn->op_str;
            cins.size = insn->size;
            insns.add(iaddr, cins);

            // Handle instruction
            switch(insn->id){
                // Jumps change control flow
                case ARM_INS_B: {
                    // Direct Branch
                    zassert(insn->detail->arm.op_count == 1 &&
                            insn->detail->arm.operands[0].type == ARM_OP_IMM);

                    zu64 jaddr = insn->detail->arm.operands[0].imm;
                    ZString bstr = ZString(insn->mnemonic) + " ";

                    // add branch insn
                    if(insn->detail->arm.cc == ARM_CC_AL){
                        block->addBranch(bstr, jaddr, "", insn->size, { jaddr });
                        // stop if unconditional
                        stop = true;
                    } else {
                        block->addBranch(bstr, jaddr, "", insn->size, { insn->address + insn->size, jaddr });
                        block = new CodeBlock(addr);
                        code.add(addr, block);
                    }

                    cins.type = CodeBlock::BRANCH;
                    cins.prefix = bstr;
                    cins.addr = jaddr;

                    ZString jname = "jump_" + HEX(jaddr);
//                    LOG("jump " << jname);
                    addLabel(jaddr, CODE, JUMP, jname);
                    total += disassembleAddress(jaddr);
                    break;
                }
                case ARM_INS_CBZ:
                case ARM_INS_CBNZ: {
                    // Conditional Branch
                    zu64 jaddr = insn->detail->arm.operands[1].imm;
                    ZString bstr = ZString(insn->mnemonic) + " " +
                            cs_reg_name(handle, insn->detail->arm.operands[0].reg) + ", ";

                    // add branch insn
                    block->addBranch(bstr, jaddr, "", insn->size, { insn->address + insn->size, jaddr });

                    cins.type = CodeBlock::BRANCH;
                    cins.prefix = bstr;
                    cins.addr = jaddr;

                    ZString jname = "jump_" + HEX(jaddr);
//                    LOG("jump " << jname);
                    addLabel(jaddr, CODE, JUMP, jname);
                    total += disassembleAddress(jaddr);

                    block = new CodeBlock(addr);
                    code.add(addr, block);
                    break;
                }
                case ARM_INS_BX:
                    // Branch register
                    if(ldr_reg != ARM_REG_INVALID && insn->detail->arm.operands[0].reg == ldr_reg){
                        // Indirect jump
                        zu64 jaddr = ldr_data & ~(zu64)1;

                        // change data type
                        data[ldr_addr].type = CPTR;
                        data[ldr_addr].data = jaddr;

                        // add branch insn
                        block->addBranch(ZString(insn->mnemonic) + " " + insn->op_str + " /* ",
                                         jaddr, " */", insn->size, { jaddr });

                        // add insn
                        cins.type = CodeBlock::BRANCH;
                        cins.prefix = ZString(insn->mnemonic) + " " + insn->op_str + " /* ";
                        cins.addr = jaddr;
                        cins.suffix = " */";

                        ZString jname = "jump_" + HEX(jaddr);
//                        LOG("jmup " << jname);
                        addLabel(jaddr, CODE, JUMP, jname, true);
                        total += disassembleAddress(jaddr);
                    } else {
                        LOG("branch register at " << HEX(insn->address));

                        // add branch insn
                        block->addCode(ZString(insn->mnemonic) + " " + insn->op_str, insn->size);

                        // add insn
                        cins.type = CodeBlock::NORMAL;
                        cins.prefix = ZString(insn->mnemonic) + " " + insn->op_str;
                    }
                    // unconditional
                    stop = true;
                    break;

                // Sometimes changes control flow
                case ARM_INS_POP:
                    // Pop stack
                    for(int i = 0; i < insn->detail->arm.op_count; ++i){
                        if(insn->detail->arm.operands[i].type == ARM_OP_REG &&
                                insn->detail->arm.operands[i].reg == ARM_REG_PC){
                            // PC popped
                            stop = true;
                        }
                    }

                    cins.type = CodeBlock::NORMAL;
                    cins.prefix = ZString(insn->mnemonic) + " " + insn->op_str;
                    break;

                // Calls reference new functions
                case ARM_INS_BL: {
                    // Branch and link
                    zassert(insn->detail->arm.op_count == 1 &&
                            insn->detail->arm.operands[0].type == ARM_OP_IMM);

                    // Direct call
                    zu64 jaddr = insn->detail->arm.operands[0].imm;

                    if(jaddr < base + image.size()){

                        cins.type = CodeBlock::BRANCH;
                        cins.prefix = ZString(insn->mnemonic) + " ";
                        cins.addr = jaddr;

                        ZString cname = "call_" + HEX(jaddr);
//                        LOG("call " << cname);
                        addLabel(jaddr, CODE, CALL, cname);
                        total += disassembleAddress(jaddr);
                    }

                    break;
                }
                case ARM_INS_BLX:
                    // Branch and link register
                    if(ldr_reg != ARM_REG_INVALID && insn->detail->arm.operands[0].reg == ldr_reg){
                        // Indirect call
                        zu64 caddr = ldr_data & ~(zu64)1;

                        // change data type
                        data[ldr_addr].type = CPTR;
                        data[ldr_addr].data = caddr;

                        // add insn
                        cins.type = CodeBlock::BRANCH;
                        cins.prefix = ZString(insn->mnemonic) + " " + insn->op_str + " /* ";
                        cins.addr = caddr;
                        cins.suffix = " */";

                        ZString cname = "call_" + HEX(caddr);
//                        LOG("call " << cname);
                        addLabel(caddr, CODE, CALL, cname, true);
                        total += disassembleAddress(caddr);
                    } else {
                        LOG("call register at " << HEX(insn->address));

                        // add branch insn
                        block->addCode(ZString(insn->mnemonic) + " " + insn->op_str, insn->size);

                        // add insn
                        cins.type = CodeBlock::NORMAL;
                        cins.prefix = ZString(insn->mnemonic) + " " + insn->op_str;
                    }
                    break;

                // Table branches
                case ARM_INS_TBB: {
                    // Table branch byte
                    if(insn->detail->arm.op_count == 1 &&
                            insn->detail->arm.operands[0].type == ARM_OP_MEM &&
                            insn->detail->arm.operands[0].mem.base == ARM_REG_PC){
                        // PC relative
                        zu64 min = ZU64_MAX;
                        for(zu64 i = 0; ; ++i){
                            // Keep track of soonest switch handler
                            if(base + offset + insn->size + i < min){
                                zu64 boff = base + offset + insn->size +
                                        (image[offset + insn->size + i] << 1);
                                // Check that offset is after the table so far
                                if(boff > base + offset + insn->size + i){
                                    min = boff;
                                    ZString bname = "switch_" + HEX(boff);
//                                    LOG("switch " << bname);
                                    addLabel(boff, CODE, SWITCH, bname);
                                    total += disassembleAddress(boff);
                                } else {
                                    break;
                                }
                            } else {
                                break;
                            }
                        }
                    }
                    // Instructions immediately after this are junk
                    stop = true;

                    cins.type = CodeBlock::NORMAL;
                    cins.prefix = ZString(insn->mnemonic) + " " + insn->op_str;
                    break;
                }

                // Load from memory
                case ARM_INS_LDR: {
                    // Load
                    if(insn->detail->arm.op_count == 2 &&
                            insn->detail->arm.operands[1].type == ARM_OP_MEM &&
                            insn->detail->arm.operands[1].mem.base == ARM_REG_PC){
                        // PC-relative load
                        zu64 pc = (base + offset + 4) & ~(zu64)3;
                        zu64 laddr = pc + insn->detail->arm.operands[1].mem.disp;
                        image.seek(laddr - base);

                        // save for next loop, next insn->may use
                        ldr_addr = laddr;
                        ldr_reg = insn->detail->arm.operands[0].reg;
                        ldr_data = image.readleu32();
                        ldr_flag = true;

                        // add insn
                        cins.type = CodeBlock::LOAD;
                        cins.prefix = ZString(insn->mnemonic) + " " + insn->op_str + " /* ";
                        cins.addr = laddr;
                        cins.suffix = " */";

                        // add label
                        ZString dname = "data_" + HEX(laddr);
                        addLabel(laddr, DATA, LDR, dname);
//                        LOG("load " << dname << " (" << HEX(ldr_data) << ")");

                        DataWord dword;
                        dword.type = VALUE;
                        dword.data = ldr_data;
                        data.add(laddr, dword);
                    }
                    break;
                }

                case ARM_INS_ADD:
                case ARM_INS_SUB: {
                    ZString istr = ZString(insn->mnemonic) + " " + insn->op_str;

                    // Some instructions are encoded differently by GNU AS
                    if(insn->size == 2 &&
                            insn->detail->arm.op_count == 3 &&
                            insn->detail->arm.operands[0].type == ARM_OP_REG &&
                            insn->detail->arm.operands[1].type == ARM_OP_REG &&
                            insn->detail->arm.operands[0].reg == insn->detail->arm.operands[1].reg &&
                            insn->detail->arm.operands[2].type == ARM_OP_IMM &&
                            insn->detail->arm.operands[2].imm < 8){
                        image.seek(offset);

                        istr = ".short 0x" + HEX(image.readleu16()) + " /* " + istr + " */ ";
//                        LOG(insn->mnemonic << " " << insn->op_str);
                    }

                    cins.type = CodeBlock::NORMAL;
                    cins.prefix = istr;
                    break;
                }

                default: {
                    // All other instructions
                    cins.type = CodeBlock::NORMAL;
                    cins.prefix = ZString(insn->mnemonic) + " " + insn->op_str;
                    break;
                }
            }

            // add instructiopn
            insns.add(iaddr, cins);

            total++;
            offset += insn->size;

            if(stop)
                break;

            if(ldr_flag){
                ldr_flag = false;
            } else {
                ldr_reg = ARM_REG_INVALID;
            }
        } else {
            ELOG("disassemble error: 0x" << HEX(base + offset) <<
                 " " << cs_strerror(cs_errno(handle)));
            break;
        }
    }

    cs_free(insn, 1);

    return total;
}

ZBinary ImageModel::makeCode(){
    ZString asem;
    asem += ".syntax unified\n";
    asem += ".cpu cortex-m3\n";
    asem += ".text\n";
    asem += ".thumb\n\n";

    ImageElement::reftype prev = ImageElement::DATA;

    for(zu64 i = 0; i <= image.size();){
        zu64 addr = base + i;
        bool labeled = false;

        // write label
        if(labels.contains(addr)){
            Label label = labels[addr];
            asem += "\n";
            if(label.thumbfunc)
                asem += ".thumb_func\n";
            asem += label.str;
            asem += ":\n";
            labeled = true;
        }

        if(insns.contains(addr)){
            if(!labeled && prev == ImageElement::RAW)
                asem += "\n";

            CodeBlock::Insn insn = insns[addr];
            if(insn.size == 0){
                ELOG("size zero ref " << HEX(base + i));
                ++i;
                continue;
            }

            ZString istr;
            switch(insn.type){
                case CodeBlock::NORMAL:
                    // Just a string
                    istr = insn.prefix;
                    break;

                case CodeBlock::BRANCH:
                case CodeBlock::LOAD:
                    // Get the label name of the target
                    if(labels.contains(insn.addr)){
                        istr = insn.prefix + labels[insn.addr].str + insn.suffix;
                    } else {
                        ELOG("missing target label " << HEX(insn.addr));
                        istr = insn .prefix + "0x" + HEX(insn.addr) + insn.suffix;
                    }
                    break;

                default:
                    break;
            }

            asem += "    ";
            asem += istr;
            asem += "\n";

            prev = ImageElement::CODE;
            i += insn.size;

        } else if(data.contains(addr)){
            if(!labeled && prev == ImageElement::RAW)
                asem += "\n";

            DataWord dword = data[addr];
            switch(dword.type){
                case VALUE:
                    asem += ("0x" + HEX(dword.data));
                    break;

                case CPTR:
                case DPTR:
                    if(labels.contains(dword.data)){
                        asem += (".word " + labels[dword.data].str);
                    } else {
                        ELOG("missing pointer label " << HEX(dword.data));
                        asem += ("0x" + HEX(dword.data));
                    }
                    break;

                default:
                    break;
            }
            asem += "\n";

            prev = ImageElement::DATA;
            i += 4;

        } else if(i < image.size()){
            if(!labeled && prev == ImageElement::CODE || prev == ImageElement::DATA)
                asem += "\n";

            asem += (".byte 0x" + HEX(image[i]) + "\n");

            prev = ImageElement::RAW;
            i += 1;

        } else {
            break;
        }
    }
    return asem;
}

void ImageModel::addLabel(zu64 addr, labeltype ltype, nametype ntype, ZString name, bool thumbfunc){
    if(labels.contains(addr)){
        if(ltype == labels[addr].ltype){
            if(ntype >= labels[addr].ntype){
                // Only change label if higher priority
                labels.add(addr, { ltype, ntype, name, thumbfunc });
            }
        } else {
            ELOG("will not change label type");
            return;
        }

    } else {
        labels.add(addr, { ltype, ntype, name, thumbfunc });
    }
}

zu64 ImageModel::_addrToOffset(zu64 addr) const {
    ZASSERT(addr >= base, "address " + HEX(addr) + " in wrong range");
    zu64 offset = addr - base;
    ZASSERT(offset < image.size(), "address " + HEX(offset) + " out of bounds");
    return offset;
}

zu64 ImageModel::_offsetToAddr(zu64 offset) const {
    return base + offset;
}
