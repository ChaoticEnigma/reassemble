#include "imagemodel.h"
#include "zlog.h"

ImageModel::ImageModel(bool oequiv, bool overbose) : equiv(oequiv), verbose(overbose), base(0){
    int mode = CS_MODE_THUMB | CS_MODE_MCLASS;
    err = cs_open(CS_ARCH_ARM, (cs_mode)mode, &handle);
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

zu64 ImageModel::addEntry(zu64 addr, ZString name, ArZ params){
    addLabel(addr, CODE, NAMED, name);
    if(params.size()){
        ZString str = "(" + ZString::join(params, ", ") + ")";
        lparams.add(addr, str);
    }
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

zu64 ImageModel::addData(zu64 addr, ZString name, zu64 words){
    addLabel(addr, DATA, NAMED, name);
    for(zu64 i = 0; i < words; ++i){
        zu64 offset = _addrToOffset(addr);
        image.seek(offset);
        zu64 word = image.readleu32();
        if(!data.contains(addr))
            data.add(addr, { VALUE, word });
        addr += 4;
    }
    return 0;
}

zu64 ImageModel::addDataPointer(zu64 addr, ZString name, zu64 words){
    zu64 offset = _addrToOffset(addr);

    if(code.contains(addr)){
        ELOG("pointer is code");
        return 0;
    }

    image.seek(offset);
    zu64 taddr = image.readleu32();

    if(base > taddr){
        ELOG("pointer in wrong range: " << HEX(addr) << " " << HEX(taddr));
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

    return addData(taddr, name, words);
}

zu64 ImageModel::disassembleAddress(zu64 start_addr, ZStack<ZString> stack){
    // Odd alignment, do not disassemble
    ZASSERT((start_addr & 0x1) == 0, ZString("not disassembling odd address ") + HEX(start_addr));

    zu64 start_offset = _addrToOffset(start_addr);

    // if this address is already disassembled we're done
    if(insns.contains(start_addr)){
        return 0;
    }
//    LOG("Disassemble from 0x" << HEX(addr) << " (" << label.str << ")");

    const zu8 *iptr = image.raw() + start_offset;
    zu64 isize = image.size() - start_offset;
    zu64 iaddr = start_addr;
    cs_insn *insn = cs_malloc(handle);
    zu64 total = 0;

    // vars for indirect jumps
    unsigned ldr_reg = ARM_REG_INVALID;
    zu64 ldr_addr = 0;
    zu64 ldr_data = 0;
    bool ldr_flag = false;

    bool stop = false;

    ZPointer<CodeBlock> block = new CodeBlock(start_addr);
    code.add(start_addr, block);

    // disassemble instructions
    while(true){
        // next instruction
        zu64 addr = iaddr;
        zu64 offset = iaddr - base;
        if(!cs_disasm_iter(handle, &iptr, &isize, &iaddr, insn)){
            // disassemble error
            ELOG("disassemble error: 0x" << HEX(base + offset) << " " <<
                 cs_strerror(cs_errno(handle)));
            // print jump stack
            for(zu64 i = 0; i < stack.size(); ++i){
                ELOG(ZLog::RAW << i << ": 0x" << stack.peek() << ZLog::NEWLN);
                stack.pop();
            }
            ZASSERT(false, "invalid instruction " + HEX(base + offset));
            break;
        }

        ZASSERT(addr == insn->address, "insn address mismatch");

        if(insns.contains(insn->address)){
            // ran into already disassembled code
            cs_free(insn, 1);
            return total;
        }

        ZString insnstr = ZString(insn->mnemonic) + " " + insn->op_str;

        if(verbose) LOG(HEX(insn->address) <<  ": " << insnstr);

        CodeBlock::Insn cins;
        cins.type = CodeBlock::NORMAL;
        cins.prefix = insnstr;
        cins.size = insn->size;
        insns.add(insn->address, cins);

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
                    block = new CodeBlock(start_addr);
                    code.add(start_addr, block);
                }

                cins.type = CodeBlock::BRANCH;
                cins.prefix = bstr;
                cins.addr = jaddr;

                addLabel(jaddr, CODE, JUMP);
                stack.push(HEX(insn->address) + " " + insnstr);
                total += disassembleAddress(jaddr, stack);
                stack.pop();
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

                addLabel(jaddr, CODE, JUMP);
                stack.push(HEX(insn->address) + " " + insnstr);
                total += disassembleAddress(jaddr, stack);
                stack.pop();

                block = new CodeBlock(start_addr);
                code.add(start_addr, block);
                break;
            }
            case ARM_INS_BX:
                // Branch register
                if(ldr_reg != ARM_REG_INVALID && insn->detail->arm.operands[0].reg == ldr_reg){
                    // Indirect jump
                    zu64 jaddr = ldr_data & ~(zu64)1;

                    if(verbose) LOG("-> " << HEX(jaddr));

                    // change data type
                    data[ldr_addr].type = CPTR;
                    data[ldr_addr].data = jaddr;

                    // add branch insn
                    ZString bstr = ZString(insn->mnemonic) + " " + insn->op_str;
                    block->addBranch(bstr + " /* ", jaddr, " */", insn->size, { jaddr });

                    // add insn
                    cins.type = CodeBlock::BRANCH;
                    cins.prefix = bstr + " /* ";
                    cins.addr = jaddr;
                    cins.suffix = " */";

                    addLabel(jaddr, CODE, JUMP, "", true);
                    stack.push(HEX(insn->address) + " " + insnstr);
                    total += disassembleAddress(jaddr, stack);
                    stack.pop();

                } else if(insn->detail->arm.operands[0].reg == ARM_REG_LR){
                    // return
                    if(verbose) LOG("<-");
                } else {
                    DLOG("branch register at " << HEX(insn->address));

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
                        if(verbose) LOG("<-");
                        // return
                        stop = true;
                    }
                }
                break;

                // Calls reference new functions
            case ARM_INS_BL: {
                // Branch and link
                zassert(insn->detail->arm.op_count == 1 &&
                        insn->detail->arm.operands[0].type == ARM_OP_IMM);

                // Direct call
                zu64 jaddr = insn->detail->arm.operands[0].imm;

                if(jaddr < base + image.size()){

                    ZString bstr = ZString(insn->mnemonic) + " ";
                    cins.type = CodeBlock::BRANCH;
                    cins.prefix = bstr;
                    cins.addr = jaddr;

                    addLabel(jaddr, CODE, CALL);
                    stack.push(HEX(insn->address) + " " + insnstr);
                    total += disassembleAddress(jaddr, stack);
                    stack.pop();
                }

                break;
            }
            case ARM_INS_BLX:
                // Branch and link register
                if(ldr_reg != ARM_REG_INVALID && insn->detail->arm.operands[0].reg == ldr_reg){
                    // Indirect call
                    zu64 caddr = ldr_data & ~(zu64)1;
                    ZString bstr = ZString(insn->mnemonic) + " " + insn->op_str;

                    if(verbose) LOG("-> " << HEX(caddr));

                    // change data type
                    data[ldr_addr].type = CPTR;
                    data[ldr_addr].data = caddr;

                    // add insn
                    cins.type = CodeBlock::BRANCH;
                    cins.prefix = bstr + " /* ";
                    cins.addr = caddr;
                    cins.suffix = " */";

                    addLabel(caddr, CODE, CALL, "", true);
                    stack.push(HEX(insn->address) + " " + insnstr);
                    total += disassembleAddress(caddr, stack);
                    stack.pop();

                } else {
                    DLOG("call register at " << HEX(insn->address));

                    // add branch insn
                    block->addCode(ZString(insn->mnemonic) + " " + insn->op_str, insn->size);
                }
                break;

                // Table branches
            case ARM_INS_TBB: {
                // Table branch byte
                if(insn->detail->arm.op_count == 1 &&
                        insn->detail->arm.operands[0].type == ARM_OP_MEM &&
                        insn->detail->arm.operands[0].mem.base == ARM_REG_PC){
                    DLOG("tbb @ " << HEX(addr));
                    // PC relative
                    zu64 pc = addr + insn->size;

                    // Keep track of lowest switch handler
                    zu64 min = ZU64_MAX;
                    // get max cases
                    zu64 maxcases = 0xFF;
                    if(switches.contains(addr)){
                        maxcases = switches[addr];
                    }
                    for(zu64 i = 0; i < maxcases; ++i){
                        if(pc + i < min &&
                                !insns.contains(pc + i) &&
                                !data.contains(pc + i) &&
                                !labels.contains(pc + i)){
                            zu64 bboff = pc - base + i;
                            zu8 bbyte = image[bboff];
                            zu64 bbaddr = _offsetToAddr(bboff);
                            zu64 baddr = pc + (bbyte << 1);
                            // Check that branch address is after the table so far
                            if(baddr > pc + i){
                                min = MIN(min, baddr);
                                DLOG("Switch Case " << HEX(bbaddr) << " -> " << HEX(baddr));
                                addLabel(baddr, CODE, SWITCH);
                                addAnnotation(bbaddr, "case switch_" + HEX_PAD(baddr, 4));
                                stack.push(HEX(insn->address) + " " + insnstr);
                                total += disassembleAddress(baddr, stack);
                                stack.pop();
                            } else {
                                // invalid branch value
                                break;
                            }
                        } else {
                            break;
                        }
                    }
                }
                // Instructions immediately after this are junk
                stop = true;
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
                    addLabel(laddr, DATA, LDR);

                    DataWord dword;
                    dword.type = VALUE;
                    dword.data = ldr_data;
                    data.add(laddr, dword);

                } else if(insn->detail->arm.operands[0].reg == ARM_REG_PC){
                    // Load into PC breaks control flow
                    stop = true;
                }
                break;
            }

            case ARM_INS_ADD:
            case ARM_INS_SUB: {
                // Some instructions are encoded differently by GNU AS
                if(!equiv &&
                        insn->size == 2 &&
                        insn->detail->arm.op_count == 3 &&
                        insn->detail->arm.operands[0].type == ARM_OP_REG &&
                        insn->detail->arm.operands[1].type == ARM_OP_REG &&
                        insn->detail->arm.operands[0].reg == insn->detail->arm.operands[1].reg &&
                        insn->detail->arm.operands[2].type == ARM_OP_IMM &&
                        insn->detail->arm.operands[2].imm < 8){
                    // Some add/sub formats will be displayed as shorts
                    image.seek(offset);
                    ZString istr = ZString(insn->mnemonic) + " " + insn->op_str;
                    cins.type = CodeBlock::NORMAL;
                    cins.prefix = ".short 0x" + HEX(image.readleu16()) + " /* " + istr + " */ ";
                } else if(insn->detail->arm.operands[0].reg == ARM_REG_PC){
                    // Add/sub to PC breaks control flow
                    stop = true;
                }
                break;
            }

            case ARM_INS_MOV:
                if(insn->detail->arm.operands[0].reg == ARM_REG_PC){
                    // Mov to PC breaks control flow
                    stop = true;
                }
                break;


            default:
                break;
        }

        // add instructiopn
        insns.add(insn->address, cins);

        total++;

        if(stop)
            break;

        if(ldr_flag){
            ldr_flag = false;
        } else {
            ldr_reg = ARM_REG_INVALID;
        }
    }

    cs_free(insn, 1);

    return total;
}

ZBinary ImageModel::makeCode(bool offsets, bool annotate){
    ZString asem;
    asem += ".syntax unified\n";
    asem += ".cpu cortex-m3\n";
    asem += ".text\n";
    asem += ".thumb\n\n";

    ImageElement::reftype prev = ImageElement::RAW;

    for(zu64 i = 0; i <= image.size();){
        zu64 addr = base + i;

        // make label
        ZString labelstr;
        if(labels.contains(addr)){
            Label label = labels[addr];
//            LOG("label " << HEX(addr) << " " << label.str);
//            asem += "\n";
            if(label.thumbfunc || (label.ltype == CODE && (label.ntype == CALL || label.ntype == NAMED))){
                labelstr += "\n";
                if(offsets) labelstr += "            ";
                labelstr += ".thumb_func\n";
            }
            if(offsets) labelstr += "            ";
            labelstr += label.str;
            labelstr += ":";
            if(lparams.contains(addr)){
                labelstr += " /* " + lparams[addr] + " */";
            }
            labelstr += "\n";
        }

        if(insns.contains(addr) && data.contains(addr)){
            ELOG("Both code and data at " << HEX_PAD(addr, 4));
        }

        if(insns.contains(addr) &&
                (forcetype.contains(addr) ? forcetype[addr] == CODE : true)){
            // Code
            if(prev != ImageElement::CODE)
                asem += "\n";
            asem += labelstr;

            CodeBlock::Insn insn = insns[addr];
//            LOG("code " << HEX(addr) << " " << insn.size << " " << insn.prefix);
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
                        if(lparams.contains(insn.addr)){
                            addAnnotation(addr, lparams[insn.addr]);
                        }
                    } else {
                        ELOG("missing target label " << HEX(insn.addr));
                        istr = insn .prefix + "0x" + HEX(insn.addr) + insn.suffix;
                    }
                    break;

                default:
                    break;
            }

            if(offsets) asem += "/*0x" + HEX_PAD(addr, 4) + "*/  ";
            asem += "    ";
            asem += istr;

            if(annotate && annotations.contains(addr)){
                asem += (" /* " + annotations[addr] + " */");
            }
            asem += "\n";

            prev = ImageElement::CODE;
            i += insn.size;

        } else if(data.contains(addr)){
            // Data
            if(prev != ImageElement::DATA)
                asem += "\n";
            asem += labelstr;

            if(offsets) asem += "/*0x" + HEX_PAD(addr, 4) + "*/  ";

            DataWord dword = data[addr];
            switch(dword.type){
                case VALUE:
                    asem += (".word 0x" + HEX_PAD(dword.data, 8));
                    if(dword.data >= base && dword.data < (base + image.size())){
                        LOG("Possible pointer @ " << HEX_PAD(addr, 4) << ": " << HEX_PAD(dword.data, 8));
                        if(!annotations.contains(addr))
                            addAnnotation(addr, "possible pointer");
                    }
                    break;

                case CPTR:
                case DPTR:
                    if(labels.contains(dword.data)){
                        asem += (".word " + labels[dword.data].str);
                    } else {
                        ELOG("missing pointer label " << HEX_PAD(dword.data, 4));
                        asem += (".word 0x" + HEX_PAD(dword.data, 4));
                    }
                    break;

                default:
                    break;
            }

            if(annotate && annotations.contains(addr)){
                asem += (" /* " + annotations[addr] + " */");
            }
            asem += "\n";

            prev = ImageElement::DATA;
            i += 4;

        } else if(i < image.size()){
            // Raw
            if(prev != ImageElement::RAW)
                asem += "\n";
            asem += labelstr;

            if(offsets) asem += "/*0x" + HEX_PAD(addr, 4) + "*/  ";
            asem += (".byte 0x" + HEX_PAD(image[i], 2));
            if(annotate && annotations.contains(i)){
                asem += (" /* " + annotations[i] + " */");
            }

            if(annotate && annotations.contains(addr)){
                asem += (" /* " + annotations[addr] + " */");
            }
            asem += "\n";

            prev = ImageElement::RAW;
            i += 1;

        } else {
            if(!labelstr.isEmpty()){
                asem += "\n";
                asem += labelstr;
            }
            break;
        }
    }
    return asem;
}

void ImageModel::addLabel(zu64 addr, labeltype ltype, nametype ntype, ZString name, bool thumbfunc){
    if(name.isEmpty()){
//        if(ntype == NAMED)
//            ntype = AUTO;

        if(ltype == CODE){
            if(ntype == CALL){
                name = "call_";
            } else if(ntype == JUMP){
                name = "jump_";
            } else if(ntype == SWITCH){
                name = "switch_";
            } else {
                name = "loc_";
            }
        } else {
            name = "data_";
        }

        name += HEX(addr);
    }

    if(labels.contains(addr)){
        // label exists
        if(ltype == labels[addr].ltype){
            // same label types
            if(ntype <= labels[addr].ntype){
                // Only change label if higher priority
                labels.add(addr, { ltype, ntype, name, labels[addr].thumbfunc || thumbfunc });
            }
        } else {
            ELOG("will not change label type " << labels[addr].ltype << " -> " << ltype << " @ " << HEX(addr));
            return;
        }

    } else {
        // new label
        labels.add(addr, { ltype, ntype, name, thumbfunc });
    }
}

void ImageModel::setSwitchLen(zu64 addr, zu64 len){
    switches[addr] = len;
}

void ImageModel::setForced(zu64 addr, ImageModel::labeltype type){
    forcetype[addr] = type;
}

void ImageModel::addAnnotation(zu64 addr, ZString note){
    ZString old;
    if(annotations.contains(addr) && !annotations[addr].isEmpty()){
        old = annotations[addr] + "; ";
    }
    if(!note.isEmpty()){
        annotations.add(addr, old + note);
    }
}

zu64 ImageModel::numInsns() const {
    return insns.size();
}

zu64 ImageModel::_addrToOffset(zu64 addr) const {
    if(!(addr >= base)){
        ZASSERT(addr >= base, "address " + HEX(addr) + " in wrong range");
    }
    zu64 offset = addr - base;
    if(!(offset < image.size())){
        ZASSERT(offset < image.size(), "address " + HEX(offset) + " out of bounds");
    }
    return offset;
}

zu64 ImageModel::_offsetToAddr(zu64 offset) const {
    return base + offset;
}
