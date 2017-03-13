#include "imagemodel.h"

#include "zlog.h"
#include "zpath.h"
#include "zfile.h"

#include <stdlib.h>

using namespace LibChaos;

#define OPT_VMA     "vma"
#define OPT_SYMBOLS "symbols"
#define OPT_DATA    "data"
#define OPT_EQUIV   "equiv"
#define OPT_VERBOSE "verbose"

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

const ZArray<OptDef> gopts = {
//    { "output",     'o', STRING },
    { OPT_VMA,      'a', INTEGER }, // Input image offset in memory.
    { OPT_SYMBOLS,  's', STRING },  // Symbol list
    { OPT_DATA,     'd', STRING },  // Data list
    { OPT_EQUIV,    'E', NONE },    // Produce equivalent (not identical) code
    { OPT_VERBOSE,  'V', NONE },    // Verbose log of disassembly
};

bool getOptions(int argc, char **argv, const ZArray<OptDef> &optdef,
                ZArray<ZString> &args, ZMap<ZString, ZString> &opts){
    bool nextarg = false;
    ZString nextname;

    for(int i = 1; i < argc; ++i){
        ZString arg = argv[i];
        if(arg.beginsWith("--") && arg.size() > 2){
            // Long option
            arg.substr(2);
            bool ok = false;
            for(zu64 j = 0; j < optdef.size(); ++j){
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
            bool noarg = true;
            // multiple flags possible
            for(zu64 k = 0; noarg && k < arg.size(); ++k){
                // check options
                for(zu64 j = 0; j < optdef.size(); ++j){
                    if(arg[k] == optdef[j].flag){
                        if(optdef[j].type == NONE){
                            opts[optdef[j].name] = "";
                        } else {
                            noarg = false;
                            arg.substr(k+1);
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
    bool ptr;
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
        if(lines[i].beginsWith("#", true))
            continue;
        ArZ line = lines[i].explode(':');
        if(line.size()){
            if(line[0].isEmpty())
                continue;

            ZString adr = line[0];
            adr.strip(' ').strip('\t').strip('\r');

            bool force = false;
            if(adr.endsWith("!")){
                force = true;
                adr.substr(0, adr.size()-1);
            }

            bool ptr = false;
            if(adr.beginsWith("*")){
                ptr = true;
                adr.substr(1);
            }
            adr.strip(' ').strip('\t').strip('\r');

            zu64 addr = adr.toUint(16);
            if(addr == ZU64_MAX)
                continue;

            if(line.size() > 1){
                ZString name = line[1];
                name.strip(' ').strip('\t').strip('\r');
                name.replace(" ", "_");
                name.replace("\t", "_");

                syms.push({ addr, name, ptr });
            } else {
                syms.push({ addr, ZString(), ptr });
            }
        }
    }

    return syms;
}

int main(int argc, char **argv){
    ZLog::logLevelStdOut(ZLog::INFO, "%clock% N %log%");
    ZLog::logLevelStdOut(ZLog::DEBUG, "%clock% D %log%\x1b[m");
    ZLog::logLevelStdErr(ZLog::ERRORS, "%clock% E [%function%|%file%:%line%] %log%");

    try {
        ZArray<ZString> args;
        ZMap<ZString, ZString> opts;
        if(!getOptions(argc, argv, gopts, args, opts))
            return 1;

        if(args.size() == 2){
            ZPath input = args[0];
            ZPath output = args[1];

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

            bool equiv = opts.contains(OPT_EQUIV);
            bool verbose = opts.contains(OPT_VERBOSE);
//            LOG("Opt: E " << equiv << ", V " << verbose);

            ImageModel model(equiv, verbose);

            zu64 vma = 0;
            if(opts.contains(OPT_VMA)){
                vma = opts[OPT_VMA].toUint(16);
                LOG("VMA: 0x" << HEX(vma));
            }
            model.loadImage(image, vma);

            zu64 total = 0;

            if(opts.contains(OPT_SYMBOLS)){
                ZArray<Symbol> csym = readSymbolFile(opts[OPT_SYMBOLS]);
                for(zu64 i = 0; i < csym.size(); ++i){
                    if(csym[i].ptr){
                        LOG("Pointer 0x" << ZString::ItoS(csym[i].addr, 16) << ": " << csym[i].name);
                        total += model.addCodePointer(csym[i].addr, csym[i].name);
                    } else {
                        LOG("Symbol 0x" << ZString::ItoS(csym[i].addr, 16) << ": " << csym[i].name);
                        total += model.addEntry(csym[i].addr, csym[i].name);
                    }
                }
            }

            if(opts.contains(OPT_DATA)){
                ZArray<Symbol> cptr = readSymbolFile(opts[OPT_DATA]);
                for(zu64 i = 0; i < cptr.size(); ++i){
                    if(cptr[i].ptr){
                        LOG("Pointer 0x" << ZString::ItoS(cptr[i].addr, 16) << ": " << cptr[i].name);
                        total += model.addDataPointer(cptr[i].addr, cptr[i].name);
                    } else {
                        LOG("Data 0x" << ZString::ItoS(cptr[i].addr, 16) << ": " << cptr[i].name);
                        total += model.addData(cptr[i].addr, cptr[i].name);
                    }
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
            RLOG("Usage: reassemble input_binary output_asm" << ZLog::NEWLN <<
                "    [-V] [-E] [-a image_vma]" << ZLog::NEWLN <<
                "    [-s symbol_address_file]" << ZLog::NEWLN <<
                "    [-d data_address_file]" << ZLog::NEWLN);
            return 1;
        }

    } catch(ZException ex){
        ELOG("exception: " << ex.what());
    }

    return 0;
}

