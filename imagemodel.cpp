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

zu64 ImageModel::disassAddr(zu64 start_addr, ZString name){
    if(name.isEmpty())
        name = "loc_" + ZString::ItoS(start_addr, 16);

    // if this address is already disassembled we're done
    if(refs.contains(start_addr - base)){
        refs[start_addr - base].label = name;
        return 0;
    }

    LOG("Disassemble from 0x" << ZString::ItoS(start_addr, 16));

    cs_insn *insn;
    zu64 offset = start_addr - base;
    zu64 total = 0;

    unsigned ldr_reg = ARM_REG_INVALID;
    zu64 ldr_data = 0;
    bool ldr_flag = false;
    bool stop = false;

    while(true){
        zu64 count = cs_disasm(handle, image.raw() + offset, 4, base + offset, 1, &insn);
        if(count > 0){
            if(refs.contains(offset)){
                // ran into already disassembled code
                return total;
            }

            ZString str = ZString() + insn->mnemonic + " " + insn->op_str;
            zu16 size = insn->size;
//            LOG("0x" << ZString::ItoS(insn->address, 16) << ": " << str);

            RefElem instr;
            instr.type = CODE;
            instr.ctype = NORMAL;
            instr.str = str;
            instr.size = insn->size;
            if(base + offset == start_addr)
                instr.label = name;

            refs.add(offset, instr);

            RefElem *tins = &refs.get(offset);

            // Handle instructions
            switch(insn->id){
                // Jumps change control flow
                case ARM_INS_B: {
                    // Direct Branch
                    zassert(insn->detail->arm.op_count == 1 &&
                            insn->detail->arm.operands[0].type == ARM_OP_IMM);
                    zu64 jaddr = insn->detail->arm.operands[0].imm;

                    // set target
                    tins->ctype = DBRANCH;
                    tins->target = jaddr;
                    tins->str = ZString(insn->mnemonic) + " ";

                    ZString jname = "jump_" + ZString::ItoS(jaddr, 16);
                    LOG("jump " << jname);
                    disassAddr(jaddr, jname);

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

                    tins->ctype = DBRANCH;
                    tins->target = addr;
                    tins->str = ZString(insn->mnemonic) + " " +
                            cs_reg_name(handle, insn->detail->arm.operands[0].reg) +
                            ", ";

                    ZString jname = "jump_" + ZString::ItoS(addr, 16);
                    LOG("jump " << jname);
                    disassAddr(addr, jname);
                    break;
                }
                case ARM_INS_BX:
                    // Branch register
                    if(ldr_reg != ARM_REG_INVALID &&
                            insn->detail->arm.operands[0].reg == ldr_reg){
                        // Indirect jump
                        zu64 addr = ldr_data - 1;
                        ZString jname = "jump_" + ZString::ItoS(addr, 16);
                        LOG("jmup " << jname);
                        disassAddr(addr, jname);
                    } else {
                        LOG("branch reg");
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
                            LOG("pop pc");
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

                    tins->ctype = DBRANCH;
                    tins->target = addr;
                    tins->str = ZString(insn->mnemonic) + " ";

                    ZString cname = "call_" + ZString::ItoS(addr, 16);
                    LOG("call " << cname);
                    disassAddr(addr, cname);
                    break;
                }
                case ARM_INS_BLX:
                    // Branch and link register
                    if(ldr_reg != ARM_REG_INVALID &&
                            insn->detail->arm.operands[0].reg == ldr_reg){
                        // Indirect call
                        zu64 addr = ldr_data - 1;
                        ZString cname = "call_" + ZString::ItoS(addr, 16);
                        LOG("call " << cname);
                        disassAddr(addr, cname);
                    }
                    break;

                // Load from memory
                case ARM_INS_LDR: {
                    // Load
                    if(insn->detail->arm.op_count == 2 &&
                            insn->detail->arm.operands[1].type == ARM_OP_MEM &&
                            insn->detail->arm.operands[1].mem.base == ARM_REG_PC){
                        // PC-relative load
                        zu64 pc = (base + offset + 4) & ~3;
                        zu64 laddr = pc + insn->detail->arm.operands[1].mem.disp;
                        image.seek(laddr - base);

                        // save for next loop, next insn may use
                        ldr_reg = insn->detail->arm.operands[0].reg;
                        ldr_data = image.readleu32();
                        ldr_flag = true;

                        ZString dname = "data_" + ZString::ItoS(laddr, 16);
                        tins->ctype = LOAD;
                        tins->target = laddr;
//                        ins->str = ZString(insn->mnemonic) + " " +
//                                cs_reg_name(handle, insn->detail->arm.operands[0].reg) +
//                                ", =" + dname;

                        LOG("load " << dname << " (" << ZString::ItoS(ldr_data, 16) << ")");

                        // add data ref
                        RefElem data;
                        data.type = DATA;
                        data.str = "0x" + ZString::ItoS(ldr_data, 16);
                        data.label = "data_" + ZString::ItoS(laddr, 16);
                        data.size = 4;
                        refs.add(laddr - base, data);
                    }
                    break;
                }

                default:
                    break;
            }

            cs_free(insn, 1);

            total += count;
            offset += size;

            if(stop)
                break;

            if(ldr_flag){
                ldr_flag = false;
            } else {
                ldr_reg = ARM_REG_INVALID;
            }
        } else {
            ELOG("disassemble error: " << cs_strerror(cs_errno(handle)));
            break;
        }
    }
    return total;
}

ZBinary ImageModel::makeCode(){
    ZBinary asem;
    asem.write((const zbyte *)".syntax unified\n", 16);
    asem.write((const zbyte *)".cpu cortex-m3\n", 15);
    asem.write((const zbyte *)".text\n", 6);
    asem.write((const zbyte *)".thumb\n\n", 8);

    reftype prev = DATA;

    for(zu64 i = 0; i < image.size();){
        if(refs.contains(i)){
            RefElem ref = refs[i];

            // add ref
            switch(ref.type){
                case CODE: {
                    if(prev == DATA || prev == RAW)
                        asem.write((const zbyte *)"\n", 1);

                    // add label, if any
                    if(!ref.label.isEmpty()){
//                        asem.write((const zbyte *)".thumb_func\n", 12);
                        asem.write(ref.label.bytes(), ref.label.size());
                        asem.write((const zbyte *)":\n", 2);
                    }

                    ZString istr = ref.str;
                    if(ref.ctype == DBRANCH){
                        // insert label in direct branch insns
                        if(refs.contains(ref.target - base)){
                            ZString lstr = refs.get(ref.target - base).label;
                            if(lstr.isEmpty()){
                                ELOG("missing jump label " <<
                                     ZString::ItoS(base + i, 16) << " " <<
                                     ZString::ItoS(ref.target, 16));
                                return ZBinary();
                            }
                            istr += lstr;
                        } else {
                            ELOG("missing jump target " << ZString::ItoS(ref.target, 16));
                            return ZBinary();
                        }
                    }

                    asem.write((const zbyte *)"    ", 4);
                    asem.write(istr.bytes(), istr.size());
                    asem.write((const zbyte *)"\n", 1);
                    break;
                }

                case DATA:
                    if(prev == CODE || prev == RAW)
                        asem.write((const zbyte *)"\n", 1);

                    if(!ref.label.isEmpty()){
                        asem.write(ref.label.bytes(), ref.label.size());
                        asem.write((const zbyte *)":\n", 2);
                    }
                    asem.write((const zbyte *)".word ", 6);
//                    asem.write((const zbyte *)".equ ", 5);
//                    asem.write(ref.label.bytes(), ref.label.size());
//                    asem.write((const zbyte *)", ", 2);
                    asem.write(ref.str.bytes(), ref.str.size());
                    asem.write((const zbyte *)"\n", 1);
                    break;

                default:
                    break;
            }

            prev = ref.type;
            i += ref.size;

        } else {
            if(prev == CODE || prev == DATA)
                asem.write((const zbyte *)"\n", 1);

            if(0){
                // read data word if word-aligned
                image.seek(i);
                ZString data = ZString("0x") + ZString::ItoS((zu64)image.readleu32(), 16);

                // add data word
                asem.write((const zbyte *)".word ", 6);
                asem.write(data.bytes(), data.size());
                asem.write((const zbyte *)"\n", 1);
                i += 4;
            } else {
                // add pad byte
                ZString data = ZString("0x") + ZString::ItoS((zu64)image[i], 16);
                asem.write((const zbyte *)".byte ", 6);
                asem.write(data.bytes(), data.size());
                asem.write((const zbyte *)"\n", 1);
                i += 1;
            }

            prev = RAW;
        }
    }
    return asem;
}
