#include "imagemodel.h"

#include "zlog.h"
#include "zpath.h"
#include "zfile.h"
#include "zoptions.h"

#include <stdlib.h>

using namespace LibChaos;

#define OPT_VMA     "vma"
#define OPT_SYMBOLS "symbols"
#define OPT_DATA    "data"
#define OPT_EQUIV   "equiv"
#define OPT_VERBOSE "verbose"
#define OPT_OFFSETS "offsets"

const ZArray<ZOptions::OptDef> optdef = {
    { OPT_VMA,      'a', ZOptions::INTEGER },   // Input image offset in memory.
    { OPT_SYMBOLS,  's', ZOptions::LIST },      // Symbol list
    { OPT_EQUIV,    'E', ZOptions::NONE },      // Produce equivalent (not identical) code
    { OPT_VERBOSE,  'V', ZOptions::NONE },      // Verbose log of disassembly
    { OPT_OFFSETS,  'O', ZOptions::NONE },      // Add disassembly offsets to output lines
};

struct Symbol {
    zu64 addr;
    ZString name;
    bool ptr;
};

int parseSymbolFile(ZPath file, ImageModel *model){
    LOG("Loading Symbol File " << file);

    ZFile inadd(file, ZFile::READ);
    if(!inadd.isOpen()){
        ELOG("failed to open symbol file");
        return 1;
    }

    ZString addstr('0', inadd.fileSize());
    inadd.read((zbyte *)addstr.c(), addstr.size());
    inadd.close();

    // current label
    ZString label;

    ArZ lines = addstr.explode('\n');
    for(zu64 i = 0; i < lines.size(); ++i){
        lines[i].strip('\r').strip('\t').strip(' ');
        if(lines[i].isEmpty())
            continue;
        // skip comments
        if(lines[i].beginsWith("#", true))
            continue;

        // read label
        if(lines[i].beginsWith("[", true)){
            // update current label
            label = ZString::substr(lines[i], lines[i].findFirst("[")+1);
            label.substr(0, label.findFirst("]"));
            label.toLower();
            LOG("Label: " << label);
            continue;
        }

        // handling for switches
        if(label == "switch"){
            if(lines[i].beginsWith("&", true)){
                lines[i].substr(1);

                ArZ line = lines[i].explode(':');
                if(line.size()){
                    if(line[0].isEmpty())
                        continue;

                    ZString adr = line[0];
                    adr.strip('\r').strip(' ').strip('\t').strip(' ');
                    zu64 addr = adr.toUint(16);

                    ZString len = line[1];
                    len.strip('\r').strip(' ').strip('\t').strip(' ');
                    zu64 length = len.toUint();

                    LOG("Max Switch Cases: " << HEX(addr) << " " << length);
                    model->setSwitchLen(addr, length);
                }
                continue;
            }
        }

        // parse symbols
        if(label == "code" || label == "data"){
            ArZ line = lines[i].explode(':');
            if(line.size()){
                if(line[0].isEmpty())
                    continue;

//                LOG("'" << lines[i] << "'");

                ZString adr = line[0];
                adr.strip('\r').strip(' ').strip('\t').strip(' ');

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
                adr.strip('\r').strip(' ').strip('\t').strip(' ');

                zu64 addr = adr.toUint(16);
                if(addr == ZU64_MAX){
                    LOG(file << ": bad offset");
                    continue;
                }

                ZString name;
                if(line.size() > 1){
                    name = line[1];
                    name.strip('\r').strip(' ').strip('\t').strip(' ');
                    name.replace(" ", "_");
                    name.replace("\t", "_");
                }

                if(label == "code"){
                    if(ptr){
                        LOG("Code Pointer 0x" << ZString::ItoS(addr, 16) << ": " << name);
                        model->addCodePointer(addr, name);
                    } else {
                        LOG("Symbol 0x" << ZString::ItoS(addr, 16) << ": " << name);
                        model->addEntry(addr, name);
                    }
                } else if(label == "data"){
                    if(ptr){
                        LOG("Data Pointer 0x" << ZString::ItoS(addr, 16) << ": " << name);
                        model->addDataPointer(addr, name);
                    } else {
                        LOG("Data 0x" << ZString::ItoS(addr, 16) << ": " << name);
                        model->addData(addr, name);
                    }
                }
            }
        }
    }

    return 0;
}

int main(int argc, char **argv){
    ZLog::logLevelStdOut(ZLog::INFO, "%clock% N %log%");
    ZLog::logLevelStdOut(ZLog::DEBUG, "%clock% D %log%\x1b[m");
    ZLog::logLevelStdErr(ZLog::ERRORS, "%clock% E [%function%|%file%:%line%] %log%");

    try {
        ZOptions options(optdef);
        if(!options.parse(argc, argv))
            return 1;

        ZArray<ZString> args = options.getArgs();
        ZMap<ZString, ZString> opts = options.getOpts();

        if(args.size() == 2){
            ZPath input = args[0];
            ZPath output = args[1];

            bool equiv = opts.contains(OPT_EQUIV);
            bool verbose = opts.contains(OPT_VERBOSE);

            ImageModel model(equiv, verbose);

            LOG("Reading");

            ZFile in(input, ZFile::READ);
            if(!in.isOpen()){
                ELOG("failed to open");
                return -1;
            }
            ZBinary image;
            in.read(image, in.fileSize());
            in.close();

            zu64 vma = 0;
            if(opts.contains(OPT_VMA)){
                vma = opts[OPT_VMA].toUint(16);
                LOG("VMA: 0x" << HEX(vma));
            }

            model.loadImage(image, vma);

            zu64 total = 0;

            LOG("Parsing");

            if(opts.contains(OPT_SYMBOLS)){
                ArZ list = opts[OPT_SYMBOLS].explode(',');
                for(auto it = list.begin(); it.more(); ++it){
                    // get symbol definitions
                    if(parseSymbolFile(it.get(), &model) != 0)
                        return 2;
                }
            }

            LOG("Insns: " << total);

            bool offsets = opts.contains(OPT_OFFSETS);
            ZBinary code = model.makeCode(offsets);
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
                "    [-s symbol_address_file]" << ZLog::NEWLN);
            return 1;
        }

    } catch(ZException ex){
        ELOG("Exception: " << ex.what());
    }

    return 0;
}

