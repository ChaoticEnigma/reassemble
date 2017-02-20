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
        zu64 vma = ZString(argv[2]).toUint();
        ZPath output = argv[3];
        ZArray<zu64> addrs;
        for(int i = 4; i < argc; ++i)
            addrs.push(ZString(argv[i]).toUint());

        ZFile in(input, ZFile::READ);
        if(!in.isOpen())
            return -1;
        ZBinary image;
        in.read(image, in.fileSize());
        in.close();

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

        ZFile out(output, ZFile::WRITE);
        if(!out.isOpen())
            return -2;
        out.write(code);
        out.close();

        return 0;
    } else {
        LOG("Usage: reassemble <input.bin> <image offset> <output.s> <entry points...>");
        return 1;
    }
}

