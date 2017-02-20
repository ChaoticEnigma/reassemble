#include "imagemodel.h"
#include "zlog.h"

#include "capstone/capstone.h"

ImageModel::ImageModel() : vma(0){
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
    ZBinary bin = inbin;
    size = bin.size();
}

zu64 ImageModel::disassAddr(zu64 addr){
    cs_insn *insn;
    zu64 count = cs_disasm(handle, code, 4, addr, 1, &insn);
    if(count > 0){
        // Check if instruction is a call
        if(cs_insn_group(handle, insn, CS_GRP_CALL)){
            if(insn->detail->arm.op_count == 1){
                if(insn->detail->arm.operands[0].type == ARM_OP_IMM){
                    zu64 addr = insn->detail->arm.operands[0].imm;
                    LOG("call " << ZString::ItoS(addr));
                    // Disassemble next function
                    disassAddr(addr);
                } else {
                    ELOG("unknown call operand: " << insn->mnemonic << " " << insn->op_str);
                }
            } else {
                ELOG("unknown call format: " << insn->mnemonic << " " << insn->op_str);
            }
        }
        cs_free(insn, 1);
    } else {
        ELOG("disassemble error");
    }
    return 0;
}

ZBinary ImageModel::makeCode(){
    return ZBinary();
}
