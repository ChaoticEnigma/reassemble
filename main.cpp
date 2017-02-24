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

    if(argc > 4){
        ZPath input = argv[1];
        zu64 vma = ZString(argv[2]).toUint(16);
        ZPath output = argv[3];
        ZPath addrs = argv[4];

//        ZArray<zu64> addrs;
//        for(int i = 4; i < argc; ++i)
//            addrs.push(ZString(argv[i]).toUint(16));

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

        ZFile inadd(addrs, ZFile::READ);
        if(!inadd.isOpen()){
            ELOG("failed to open");
            return -1;
        }
        ZString addstr('0', inadd.fileSize());
        inadd.read((zbyte *)addstr.c(), addstr.size());
        inadd.close();
        ArZ lines = addstr.explode('\n');
        LOG("lines " << lines.size());
        for(zu64 i = 0; i < lines.size(); ++i){
            ArZ line = lines[i].explode(':');
            if(line.size()){
                if(line[0].isEmpty())
                    continue;
                zu64 addr = line[0].strip(' ').toUint(16);
                if(line.size() > 1 && !line[1].strip(' ').isEmpty()){
                    ZString name = line[1].strip(' ');
                    LOG("Entry " << ZString::ItoS(addr, 16) << " " << name);
                    model.addEntry(addr, name);
                } else {
                    model.addEntry(addr);
                }
            }
        }

//        for(zu64 i = 0; i < addrs.size(); ++i)
//            model.addEntry(addrs[i]);

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

