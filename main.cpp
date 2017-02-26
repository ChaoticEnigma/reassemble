#include "imagemodel.h"

#include "zlog.h"
#include "zpath.h"
#include "zfile.h"

#include <stdlib.h>

using namespace LibChaos;

enum OptType {
    NONE,
    STRING,
    INTEGER,
};

struct OptDef {
    ZString name;
    char flag;
    OptType type;
};

struct Option {
    OptType type;
    union {
        ZString string;
        zs64 integer;
    };
};

const OptDef gopts[] = {
//    { "output",     'o', STRING },
    { "vma",        'a', INTEGER },
    { "symbols",    's', STRING },
    { "pointers",   'p', STRING },
};

bool getOptions(int argc, char **argv, const OptDef *optdef, int nopts,
                ZArray<ZString> &args, ZMap<ZString, ZString> &opts){
    bool nextarg = false;
    ZString nextname;

    for(int i = 1; i < argc; ++i){
        ZString arg = argv[i];
        if(arg.beginsWith("--") && arg.size() > 2){
            // Long option
            arg.substr(2);
            bool ok = false;
            for(int j = 0; j < nopts; ++j){
                ZString pref = optdef[j].name + "=";
                if(arg == optdef[j].name){
                    if(optdef[j].type == NONE){
                        opts[optdef[j].name] = "";
                    } else {
                        nextname = optdef[j].name;
                        nextarg = true;
                    }
                    ok = true;
                    break;
                } else if(arg.beginsWith(pref)){
                    arg.substr(pref.size());
                    opts[optdef[j].name] = arg;
                    ok = true;
                }
            }
            if(!ok){
                LOG("error: unknown long option: " << arg);
                return false;
            }

        } else if(arg.beginsWith("-") && arg.size() > 1){
            // Flag option
            arg.substr(1);
            bool ok = false;
            for(int j = 0; j < nopts; ++j){
                if(arg[0] == optdef[j].flag){
                    if(optdef[j].type == NONE){
                        if(arg.size() == 1){
                            opts[optdef[j].name] = "";
                        } else {
                            LOG("error: incorrect flag option: " << arg);
                            return false;
                        }
                    } else {
                        arg.substr(1);
                        if(arg.isEmpty()){
                            nextname = optdef[j].name;
                            nextarg = true;
                        } else {
                            opts[optdef[j].name] = arg;
                        }
                    }
                    ok = true;
                    break;
                }
            }
            if(!ok){
                LOG("error: unknown flag option: " << arg);
                return false;
            }

        } else if(nextarg){
            // Option argument
            opts[nextname] = arg;
            nextarg = false;

        } else {
            // Normal arg
            args.push(arg);
        }
    }

    if(nextarg){
        LOG("error: no value for option: " << nextname);
        return false;
    }
    return true;
}

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

    ZArray<ZString> args;
    ZMap<ZString, ZString> opts;
    if(!getOptions(argc, argv, gopts, 3, args, opts))
        return 1;

//    LOG("args " << args.size());
//    for(zu64 i = 0; i < args.size(); ++i){
//        LOG(args[i]);
//    }
//    LOG("opts " << opts.size());
//    for(auto it = opts.begin(); it.more(); it.advance()){
//        LOG(it.get() << " " << opts[it.get()]);
//    }

    if(args.size() == 2){
        ZPath input = args[0];
        ZPath output = args[1];

        zu64 vma = 0;
        if(opts.contains("vma")){
            vma = opts["vma"].toUint(16);
        }

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

        if(opts.contains("symbols")){
            ZArray<Symbol> csym = readSymbolFile(opts["symbols"]);
            for(zu64 i = 0; i < csym.size(); ++i){
                LOG("Entry 0x" << ZString::ItoS(csym[i].addr, 16) << ": " << csym[i].name);
                total += model.addEntry(csym[i].addr, csym[i].name);
            }
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

    } else {
        LOG("Usage: reassemble <input.bin> <output.s> [-a <image offset>] [-s <symbol list file>]");
        return 1;
    }

    return 0;
}

