#include "imagemodel.h"

#include "zlog.h"
#include "zpath.h"
#include "zfile.h"

#include <stdlib.h>

using namespace LibChaos;

int main(int argc, char **argv){
    ZLog::logLevelStdOut(ZLog::INFO, "%clock% N %log%");
    ZLog::logLevelStdOut(ZLog::DEBUG, "%clock% D %log%\x1b[m");
    ZLog::logLevelStdErr(ZLog::ERRORS, "%clock% E [%function%|%file%:%line%] %log%");

    if(argc > 2){
        ZPath input = argv[1];
        zu64 vma = ZString(argv[2]).toUint(16);
        ZPath output = argv[3];
        ZArray<zu64> addrs;
        for(int i = 4; i < argc; ++i)
            addrs.push(ZString(argv[i]).toUint(16));

        LOG("Reading");
        ZFile in(input, ZFile::READ);
        if(!in.isOpen()){
            ELOG("failed to open");
            return -1;
        }
        ZBinary image;
        in.read(image, in.fileSize());
        in.close();

        LOG("Parsing");
        ImageModel model;
        model.loadImage(image, vma);
        for(zu64 i = 0; i < addrs.size(); ++i)
            model.disassAddr(addrs[i]);

//        ZString odcmd = "arm-none-eabi-objdump -Dz -b binary" +
//                " -m arm -M force-thumb" +
//                " --adjust-vma=0x" + ZString::ItoS(vma, 16) + "\"" +  + "\"";
//        LOG(odcmd);
//        system(odcmd.cc());

        ZBinary code = model.makeCode();

        LOG("Output: " << code.size());

        LOG("Writing");
        ZFile out(output, ZFile::WRITE | ZFile::TRUNCATE);
        if(!out.isOpen()){
            ELOG("failed to open");
            return -2;
        }
        if(out.write(code) != code.size()){
            ELOG("failed to write");
        }
        out.close();

        return 0;
    } else {
        LOG("Usage: reassemble <input.bin> <image offset> <output.s> <entry points...>");
        return 1;
    }
}

