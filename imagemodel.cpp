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

zu64 ImageModel::disassAddr(zu64 start_addr){
    LOG("Disassemble from 0x" << ZString::ItoS(start_addr, 16));

    cs_insn *insn;
    zu64 offset = start_addr - base;
    zu64 total = 0;

    unsigned ldr_reg = ARM_REG_INVALID;
    zu64 ldr_data = 0;
    bool ldr_flag = false;

    while(true){
        zu64 count = cs_disasm(handle, image.raw() + offset, 4, base + offset, 1, &insn);
        if(count > 0){
            ZString str = ZString() +
                    "0x" + ZString::ItoS(insn->address, 16) + ": " +
                    insn->mnemonic + " " + insn->op_str;
            zu16 size = insn->size;
//            LOG(str);

            // Handle instructions
            switch(insn->id){
                // Jumps change control flow
                case ARM_INS_B:
                    // Branch
                    if(insn->detail->arm.op_count == 1 &&
                            insn->detail->arm.operands[0].type == ARM_OP_IMM){
                        // Direct jump
                        zu64 addr = insn->detail->arm.operands[0].imm;
                        LOG("jump 0x" << ZString::ItoS(addr, 16));
                        disassAddr(addr);
                    } else {
                        ELOG("unknown b format: " << str);
                    }
                    // Stop if unconditional
                    if(insn->detail->arm.cc == ARM_CC_AL){
                        return count;
                    }
                    break;
                case ARM_INS_BX:
                    // Branch register
                    if(ldr_reg != ARM_REG_INVALID &&
                            insn->detail->arm.operands[0].reg == ldr_reg){
                        // Indirect jump
                        zu64 addr = ldr_data - 1;
                        LOG("jump 0x" << ZString::ItoS(addr, 16));
                        disassAddr(addr);
                    } else {
                        LOG("branch reg");
                    }
                    return total;
                    break;

                // Sometimes changes control flow
                case ARM_INS_POP:
                    // Pop stack
                    for(int i = 0; i < insn->detail->arm.op_count; ++i){
                        if(insn->detail->arm.operands[i].type == ARM_OP_REG &&
                                insn->detail->arm.operands[i].reg == ARM_REG_PC){
                            // PC popped
                            LOG("pop pc");
                            return total;
                        }
                    }
                    break;

                // Calls reference new functions
                case ARM_INS_BL:
                    // Branch and link
                    if(insn->detail->arm.op_count == 1 &&
                            insn->detail->arm.operands[0].type == ARM_OP_IMM){
                        // Direct call
                        zu64 addr = insn->detail->arm.operands[0].imm;
                        LOG("call 0x" << ZString::ItoS(addr, 16));
                        disassAddr(addr);
                    } else {
                        ELOG("unknown bl format: " << str);
                    }
                    break;
                case ARM_INS_BLX:
                    // Branch and link register
                    if(ldr_reg != ARM_REG_INVALID &&
                            insn->detail->arm.operands[0].reg == ldr_reg){
                        // Indirect call
                        zu64 addr = ldr_data - 1;
                        LOG("call 0x" << ZString::ItoS(addr, 16));
                        disassAddr(addr);
                    }
                    break;

                // Load from memory
                case ARM_INS_LDR:
                    // Load
                    if(insn->detail->arm.op_count == 2 &&
                            insn->detail->arm.operands[1].type == ARM_OP_MEM &&
                            insn->detail->arm.operands[1].mem.base == ARM_REG_PC){
                        // PC-relative load
                        zu64 pc = (base + offset + 4) & ~3;
                        zu64 laddr = pc + insn->detail->arm.operands[1].mem.disp;
                        image.seek(laddr - base);
                        ldr_reg = insn->detail->arm.operands[0].reg;
                        ldr_data = image.readleu32();
                        ldr_flag = true;
                        image.rewind();
                        LOG("load 0x" << ZString::ItoS(laddr, 16) <<
                            " (" << ZString::ItoS(ldr_data, 16) << ")");
                    }
                    break;

                default:
                    break;
            }

            total += count;
            offset += size;

            if(ldr_flag){
                ldr_flag = false;
            } else {
                ldr_reg = ARM_REG_INVALID;
            }

            cs_free(insn, 1);
        } else {
            ELOG("disassemble error");
            break;
        }
    }
    return total;
}

ZBinary ImageModel::makeCode(){
    return ZBinary();
}
