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

zu64 ImageModel::addEntry(zu64 start_addr, ZString name){
    return disassembleAddress(start_addr, { ImageElement::NAMED, name });
}

zu64 ImageModel::addCodePointer(zu64 ptr_addr, ZString name){
    zu64 offset = _addrToOffset(ptr_addr);

    if(refs.contains(offset)){
        if(refs[offset].type == ImageElement::CODE){
            ELOG("pointer is code");
            return 0;
        }
    } else {
        ImageElement data;
        data.type = ImageElement::DATA;
        data.size = 4;
        data.label = "data_" + HEX(ptr_addr);
        refs.add(offset, data);
    }

    image.seek(offset);
    zu64 tar = image.readleu32() & ~(zu64)1;

    if(base > tar){
        ELOG("pointer in wrong range");
        return 0;
    }
    zu64 toffset = tar - base;
    if(toffset >= image.size()){
        ELOG("pointer out of bounds " << HEX(ptr_addr) << " " << HEX(tar));
        return 0;
    }

    ImageElement *ref = &refs[offset];
    ref->str = ".word ";
    ref->ftype = ImageElement::F_TARGET;
    ref->target = tar;

    zu64 total = disassembleAddress(tar, { ImageElement::CALL, name });
    refs[toffset].flags |= ImageElement::THUMBFUNC;
    return total;
}

zu64 ImageModel::addData(zu64 data_addr, ZString name){
    zu64 offset = _addrToOffset(data_addr);

    if(!refs.contains(offset)){
        ImageElement data;
        data.type = ImageElement::RAW;
        if(offset == image.size()){
            data.size = 1;
            data.str = "";
        } else {
            data.size = 1;
            data.str = ".byte 0x" + HEX(image[offset]);
        }
        data.flags = 0;

        if(name.isEmpty())
            data.label = "data_" + HEX(data_addr);
        else
            data.label = name;

        refs.add(offset, data);
    }
    return 0;
}

zu64 ImageModel::addDataPointer(zu64 ptr_addr, ZString name){
    zu64 offset = _addrToOffset(ptr_addr);

    if(refs.contains(offset)){
        if(refs[offset].type == ImageElement::CODE){
            ELOG("pointer is code");
            return 0;
        }
    } else {
        ImageElement data;
        data.type = ImageElement::DATA;
        data.size = 4;
        data.label = "data_" + HEX(ptr_addr);
        refs.add(offset, data);
    }

    image.seek(offset);
    zu64 tar = image.readleu32();

    if(base > tar){
        ELOG("pointer in wrong range");
        return 0;
    }
    zu64 toffset = tar - base;
    if(toffset > image.size()){
        ELOG("pointer out of bounds " << HEX(ptr_addr) << " " << HEX(tar));
        return 0;
    }

    ImageElement *ref = &refs[offset];
    ref->size = 4;
    ref->str = ".word ";
    ref->ftype = ImageElement::F_TARGET;
    ref->target = tar;

    return addData(tar, name);
}

zu64 ImageModel::disassembleAddress(zu64 start_addr, Label label){
    zu64 offset = _addrToOffset(start_addr);

    // if this address is already disassembled we're done
    if(refs.contains(offset)){
        // set higher-priority tag
        if(label.type <= refs[offset].ltype){
//            if(refs[start_addr - base].label != label.str)
//                LOG("Rename " << refs[start_addr - base].label << " " << label.str);
            refs[offset].ltype = label.type;
            if(label.str.isEmpty())
                refs[offset].label = "loc_" + HEX(start_addr);
            else
                refs[offset].label = label.str;
        }
        return 0;
    }

    LOG("Disassemble from 0x" << HEX(start_addr) << " (" << label.str << ")");

    const zu8 *iptr = image.raw() + offset;
    zu64 isize = image.size() - offset;
    zu64 iaddr = base + offset;
    cs_insn *insn = cs_malloc(handle);
    zu64 total = 0;

    unsigned ldr_reg = ARM_REG_INVALID;
    zu64 ldr_addr = 0;
    zu64 ldr_data = 0;
    bool ldr_flag = false;
    bool stop = false;

    while(true){
        // disassemble instructions
        if(cs_disasm_iter(handle, &iptr, &isize, &iaddr, insn)){
            if(refs.contains(offset)){
                // ran into already disassembled code
                cs_free(insn, 1);
                return total;
            }

            ImageElement instr;
            instr.type = ImageElement::CODE;
            instr.size = insn->size;
            instr.str = ZString(insn->mnemonic) + " " + insn->op_str;
//            LOG("0x" << HEX(insn->address) << ": " << instr.str);

            instr.ctype = ImageElement::NORMAL;
            instr.ftype = ImageElement::F_STRING;
            instr.flags = 0;

            instr.ltype = ImageElement::LNONE;
            if(base + offset == start_addr){
                instr.ltype = label.type;
                if(label.str.isEmpty())
                    instr.label = "loc_" + HEX(start_addr);
                else
                    instr.label = label.str;
            }

            refs.add(offset, instr);

            ImageElement *tins = &refs.get(offset);

            // Handle instruction
            switch(insn->id){
                // Jumps change control flow
                case ARM_INS_B: {
                    // Direct Branch
                    zassert(insn->detail->arm.op_count == 1 &&
                            insn->detail->arm.operands[0].type == ARM_OP_IMM);
                    zu64 jaddr = insn->detail->arm.operands[0].imm;

                    // set target
                    tins->ftype = ImageElement::F_TARGET;
                    tins->target = jaddr;
                    tins->str = ZString(insn->mnemonic) + " ";

                    ZString jname = "jump_" + HEX(jaddr);
//                    LOG("jump " << jname);
                    total += disassembleAddress(jaddr, { ImageElement::JUMP, jname });

                    // Stop if unconditional
                    if(insn->detail->arm.cc == ARM_CC_AL){
                        stop = true;
                    }
                    break;
                }
                case ARM_INS_CBZ:
                case ARM_INS_CBNZ: {
                    // Conditional Branch
                    zu64 addr = insn->detail->arm.operands[1].imm;

                    tins->ftype = ImageElement::F_TARGET;
                    tins->target = addr;
                    tins->str = ZString(insn->mnemonic) + " " +
                            cs_reg_name(handle, insn->detail->arm.operands[0].reg) +
                            ", ";

                    ZString jname = "jump_" + HEX(addr);
//                    LOG("jump " << jname);
                    total += disassembleAddress(addr, { ImageElement::JUMP, jname });
                    break;
                }
                case ARM_INS_BX:
                    // Branch register
                    if(ldr_reg != ARM_REG_INVALID && insn->detail->arm.operands[0].reg == ldr_reg){
                        // Indirect jump
                        zu64 addr = ldr_data & ~(zu64)1;

                        tins->ftype = ImageElement::F_TARGET;
                        tins->target = addr;
                        tins->str += " /* ";
                        tins->suffix = " */ ";

                        refs[ldr_addr].ftype = ImageElement::F_TARGET;
                        refs[ldr_addr].str = ".word ";
                        refs[ldr_addr].target = addr;

                        ZString jname = "jump_" + HEX(addr);
//                        LOG("jmup " << jname);
                        total += disassembleAddress(addr, { ImageElement::JUMP, jname });

                        // target must have .thumb_func directive
                        refs[addr - base].flags |= ImageElement::THUMBFUNC;

                    } else {
//                        LOG("branch reg");
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
//                            LOG("pop pc");
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
                    zu64 addr = insn->detail->arm.operands[0].imm;

                    if(addr < base + image.size()){
                        tins->ftype = ImageElement::F_TARGET;
                        tins->target = addr;
                        tins->str = ZString(insn->mnemonic) + " ";

                        ZString cname = "call_" + HEX(addr);
//                        LOG("call " << cname);
                        total += disassembleAddress(addr, { ImageElement::CALL, cname });
                    }
                    break;
                }
                case ARM_INS_BLX:
                    // Branch and link register
                    if(ldr_reg != ARM_REG_INVALID && insn->detail->arm.operands[0].reg == ldr_reg){
                        // Indirect call
                        zu64 addr = ldr_data & ~(zu64)1;

                        tins->ftype = ImageElement::F_TARGET;
                        tins->target = addr;
                        tins->str += " /* ";
                        tins->suffix = " */ ";

                        refs[ldr_addr].ftype = ImageElement::F_TARGET;
                        refs[ldr_addr].str = ".word ";
                        refs[ldr_addr].target = addr;

                        ZString cname = "call_" + HEX(addr);
//                        LOG("call " << cname);
                        total += disassembleAddress(addr, { ImageElement::CALL, cname });

                        // target must have .thumb_func directive
                        refs[addr - base].flags |= ImageElement::THUMBFUNC;
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
                                    total += disassembleAddress(boff, { ImageElement::SWITCH, bname});
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
                        ldr_addr = laddr - base;
                        ldr_reg = insn->detail->arm.operands[0].reg;
                        ldr_data = image.readleu32();
                        ldr_flag = true;

                        ZString dname = "data_" + HEX(laddr);
                        tins->ftype = ImageElement::F_TARGET;
                        tins->target = laddr;
                        tins->str += " /* ";
                        tins->suffix = " */ ";
//                        tins->str = ZString(insn->mnemonic) + " " +
//                                cs_reg_name(handle, insn->detail->arm.operands[0].reg) +
//                                ", =";

//                        LOG("load " << dname << " (" << HEX(ldr_data) << ")");

                        // add data ref
                        ImageElement data;
                        data.type = ImageElement::DATA;
                        data.size = 4;
                        data.str = ".word 0x" + HEX(ldr_data);
                        data.label = "data_" + HEX(laddr);
                        refs.add(ldr_addr, data);
                    }
                    break;
                }

                // Some instructions are encoded differently by GNU AS
                case ARM_INS_ADD:
                case ARM_INS_SUB:
                    if(insn->size == 2 &&
                            insn->detail->arm.op_count == 3 &&
                            insn->detail->arm.operands[0].type == ARM_OP_REG &&
                            insn->detail->arm.operands[1].type == ARM_OP_REG &&
                            insn->detail->arm.operands[0].reg == insn->detail->arm.operands[1].reg &&
                            insn->detail->arm.operands[2].type == ARM_OP_IMM &&
                            insn->detail->arm.operands[2].imm < 8){
                        image.seek(offset);
                        tins->str = ".short 0x" + ZString::ItoS((zu64)image.readleu16(), 16) +
                                " /* " + tins->str + " */ ";
                        LOG(insn->mnemonic << " " << insn->op_str);
                    }
                    break;

                default:
                    break;
            }

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
    ZBinary asem;
    asem.write((const zbyte *)".syntax unified\n", 16);
    asem.write((const zbyte *)".cpu cortex-m3\n", 15);
    asem.write((const zbyte *)".text\n", 6);
    asem.write((const zbyte *)".thumb\n\n", 8);

    ImageElement::reftype prev = ImageElement::DATA;

    for(zu64 i = 0; i <= image.size();){
        if(refs.contains(i)){
            ImageElement ref = refs[i];
            if(ref.size == 0){
                ELOG("size zero ref " << HEX(base + i));
                ++i;
                continue;
            }

            if(prev != ref.type || prev == ImageElement::RAW){
                asem.write((const zbyte *)"\n", 1);
            }

            if(ref.flags & ImageElement::THUMBFUNC){
                asem.write((const zbyte *)".thumb_func\n", 12);
            }

            // add label, if any
            if(!ref.label.isEmpty()){
//                asem.write((const zbyte *)".thumb_func\n", 12);
                asem.write(ref.label.bytes(), ref.label.size());
                asem.write((const zbyte *)":\n", 2);
            }

            ZString istr = ref.str;
            switch(ref.ftype){
                case ImageElement::F_STRING:
                    // Just a string
                    istr = ref.str;
                    break;

                case ImageElement::F_TARGET:
                    // Get the label name of the target
                    if(refs.contains(ref.target - base)){
                        ZString lstr = refs.get(ref.target - base).label;
                        if(lstr.isEmpty()){
                            ELOG("missing target label " <<
                                 HEX(base + i) << " " << HEX(ref.target));
                            lstr = "0x" + HEX(ref.target);
                        }
                        istr = ref.str + lstr + ref.suffix;
                    } else {
                        ELOG("missing target " << HEX(ref.target));
                        istr = ref.str + "0x" + HEX(ref.target) + ref.suffix;
                    }
                    break;

                default:
                    break;
            }

            if(ref.type == ImageElement::CODE){
                asem.write((const zbyte *)"    ", 4);
            }
            asem.write(istr.bytes(), istr.size());
            asem.write((const zbyte *)"\n", 1);

            prev = ref.type;
            i += ref.size;

        } else if(i < image.size()){
            if(prev == ImageElement::CODE || prev == ImageElement::DATA)
                asem.write((const zbyte *)"\n", 1);

            // add pad byte
            ZString data = "0x" + HEX(image[i]);
            asem.write((const zbyte *)".byte ", 6);
            asem.write(data.bytes(), data.size());
            asem.write((const zbyte *)"\n", 1);
            i += 1;

            prev = ImageElement::RAW;
        } else {
            break;
        }
    }
    return asem;
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
