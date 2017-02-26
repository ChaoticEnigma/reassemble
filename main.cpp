#include "imagemodel.h"

#include "zlog.h"
#include "zpath.h"
#include "zfile.h"

#include <stdlib.h>

using namespace LibChaos;

struct Symbol {
    zu64 addr;
    ZString name;
};

ZArray<Symbol> readSymbolFile(ZPath file){
    ZArray<Symbol> syms;

    ZFile inadd(file, ZFile::READ);
    if(!inadd.isOpen()){
        ELOG("failed to open");
        return ZArray<Symbol>();
    }

    ZString addstr('0', inadd.fileSize());
    inadd.read((zbyte *)addstr.c(), addstr.size());
    inadd.close();

    ArZ lines = addstr.explode('\n');
    for(zu64 i = 0; i < lines.size(); ++i){
        ArZ line = lines[i].explode(':');
        if(line.size()){
            if(line[0].isEmpty())
                continue;

            zu64 addr = line[0].strip(' ').strip('\t').strip('\r').toUint(16);
            if(addr == ZU64_MAX)
                continue;

            if(line.size() > 1){
                ZString name = line[1];
                name.strip(' ').strip('\t').strip('\r');
                name.replace(" ", "_");
                name.replace("\t", "_");

                syms.push({ addr, name });
            } else {
                syms.push({ addr, ZString() });
            }
        }
    }

    return syms;
}

int main(int argc, char **argv){
    ZLog::logLevelStdOut(ZLog::INFO, "%clock% N %log%");
    ZLog::logLevelStdOut(ZLog::DEBUG, "%clock% D %log%\x1b[m");
    ZLog::logLevelStdErr(ZLog::ERRORS, "%clock% E [%function%|%file%:%line%] %log%");

    if(argc == 5){
        ZPath input = argv[1];
        zu64 vma = ZString(argv[2]).toUint(16);
        ZPath output = argv[3];
        ZPath addrs = argv[4];
//        ZPath datas = argv[5];

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

        zu64 total = 0;
        ZArray<Symbol> csym = readSymbolFile(addrs);
        for(zu64 i = 0; i < csym.size(); ++i){
            LOG("Entry 0x" << ZString::ItoS(csym[i].addr, 16) << ": " << csym[i].name);
            total += model.addEntry(csym[i].addr, csym[i].name);
        }
        LOG("Insns: " << total);

        ZBinary code = model.makeCode();

        LOG("Output: " << code.size() << " bytes");

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

