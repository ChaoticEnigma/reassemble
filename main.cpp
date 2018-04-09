#include "imagemodel.h"

#include "zlog.h"
#include "zpath.h"
#include "zfile.h"
#include "zoptions.h"

#include <stdlib.h>

using namespace LibChaos;

#define OPT_VMA         "vma"
#define OPT_SYMBOLS     "symbols"
#define OPT_DATA        "data"
#define OPT_EQUIV       "equiv"
#define OPT_VERBOSE     "verbose"
#define OPT_OFFSETS     "offsets"
#define OPT_ANNOTATE    "annotate"

const ZArray<ZOptions::OptDef> optdef = {
    { OPT_VMA,      'a', ZOptions::INTEGER },   // Input image offset in memory.
    { OPT_SYMBOLS,  's', ZOptions::LIST },      // Symbol list
    { OPT_EQUIV,    'E', ZOptions::NONE },      // Produce equivalent (not identical) code
    { OPT_VERBOSE,  'V', ZOptions::NONE },      // Verbose log of disassembly
    { OPT_OFFSETS,  'O', ZOptions::NONE },      // Add disassembly offsets to output lines
    { OPT_ANNOTATE, 'A', ZOptions::NONE },      // Add more annotations to disassembly output
};

struct Symbol {
    zu64 addr;
    ZString name;
    bool ptr;
};

enum Section {
    SEC_NONE,
    SEC_CODE,
    SEC_DATA,
    SEC_SWITCH,
    SEC_ANNOTE,
};

zu64 parseSymbolFile(ZPath file, ImageModel *model){
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
    Section section = SEC_NONE;
    zu64 total = 0;
    zu64 prevaddr = 0;

    // loop over lines
    ArZ lines = addstr.explode('\n');
    for(zu64 i = 0; i < lines.size(); ++i){
        // strip whitespace
        lines[i].strip('\r').strip('\t').strip(' ');
        if(lines[i].isEmpty())
            continue;
        // skip comments
        if(lines[i].beginsWith("#", true))
            continue;

        // read label
        if(lines[i].beginsWith("[", true)){
            // update current label
            ZString label = ZString::substr(lines[i], lines[i].findFirst("[")+1);
            label.substr(0, label.findFirst("]"));
            label.toLower();
            LOG("Label: " << label);
            if(label == "code"){
                section = SEC_CODE;
            } else if(label == "data"){
                section = SEC_DATA;
            } else if(label == "switch"){
                section = SEC_SWITCH;
            } else if(label == "annote"){
                section = SEC_ANNOTE;
            } else {
                ELOG("Invalid label!");
                break;
            }
            continue;
        }

        bool stop = false;
        switch(section){
            case SEC_SWITCH:
                if(lines[i].beginsWith("&", true)){
                    lines[i].substr(1);

                    ArZ line = lines[i].explode(':');
                    if(line.size()){
                        if(line[0].isEmpty())
                            break;

                        ZString adr = line[0];
                        adr.strip('\r').strip(' ').strip('\t').strip(' ');
                        zu64 addr;
                        if(adr.beginsWith("+")){
                            zu64 tmp = adr.substr(1).toUint(16);
                            if(tmp == ZU64_MAX){
                                LOG(file << ": bad offset");
                                stop = true;
                                break;
                            }
                            addr = prevaddr + tmp;
                        } else {
                            addr = adr.toUint(16);
                            if(addr == ZU64_MAX){
                                LOG(file << ": bad offset");
                                stop = true;
                                break;
                            }
                        }
                        prevaddr = addr;

                        ZString len = line[1];
                        len.strip('\r').strip(' ').strip('\t').strip(' ');
                        zu64 length = len.toUint();

                        LOG("Max Switch Cases: " << HEX(addr) << " " << length);
                        model->setSwitchLen(addr, length);
                    }
                }
                break;

            case SEC_CODE: {
                // format:
                // [*]address[:name [.type [count]]]

                ArZ line = lines[i].explode(':');
                if(line.size() > 2){
                    ELOG("Invalid line: " << lines[i]);
                    stop = true;
                } else if(line.size()){
                    if(line[0].isEmpty())
                        break;

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

                    zu64 addr;
                    if(adr.beginsWith("+")){
                        zu64 tmp = adr.substr(1).toUint(16);
                        if(tmp == ZU64_MAX){
                            LOG(file << ": bad offset");
                            stop = true;
                            break;
                        }
                        addr = prevaddr + tmp;
                    } else {
                        addr = adr.toUint(16);
                        if(addr == ZU64_MAX){
                            LOG(file << ": bad offset");
                            stop = true;
                            break;
                        }
                    }
                    prevaddr = addr;

                    ZString name;
                    ArZ args;

                    if(line.size() > 1){
                        ZString dstr = line[1];
                        dstr.strip('\r').strip(' ').strip('\t').strip(' ');
                        ArZ desc = dstr.explode(' ');

                        if(desc.size() && !desc[0].isEmpty()){
                            name = desc[0];
                        }

                        for(zu64 j = 1; j < desc.size(); ++j){
                            ZString arg = desc[j];
                            arg.strip('\r').strip(' ').strip('\t').strip(' ');
                            args.push(arg);
                        }
                    }


                    if(ptr){
                        zu64 count = model->addCodePointer(addr, name);
                        total += count;
                        LOG("Code Pointer 0x" << ZString::ItoS(addr, 16) << ": " << name << " [" << count << " insns]");
                        if(force){
                            model->setForced(addr, ImageModel::DATA);
                        }
                    } else {
                        zu64 count = model->addEntry(addr, name, args);
                        total += count;
                        LOG("Symbol 0x" << ZString::ItoS(addr, 16) << ": " << name << (args.size() ? "(" + ZString::join(args, ", ") + ")" : "") << " [" << count << " insns]");
                    }
                }
                break;
            }

            case SEC_DATA: {
                // format:
                // [*]address[:name [args..]]

                ArZ line = lines[i].explode(':');
                if(line.size() > 2){
                    ELOG("Invalid line: " << lines[i]);
                    stop = true;
                } else if(line.size()){
                    if(line[0].isEmpty())
                        break;

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

                    zu64 addr;
                    if(adr.beginsWith("+")){
                        zu64 tmp = adr.substr(1).toUint(16);
                        if(tmp == ZU64_MAX){
                            LOG(file << ": bad offset");
                            stop = true;
                            break;
                        }
                        addr = prevaddr + tmp;
                    } else {
                        addr = adr.toUint(16);
                        if(addr == ZU64_MAX){
                            LOG(file << ": bad offset");
                            stop = true;
                            break;
                        }
                    }
                    prevaddr = addr;

                    ZString name;
                    ZString type = ".byte";
                    zu64 size = 1;

                    if(line.size() > 1){
                        ZString dstr = line[1];
                        dstr.strip('\r').strip(' ').strip('\t').strip(' ');
                        ArZ desc = dstr.explode(' ');
                        if(desc.size() > 3){
                            ELOG("Invalid desc: " << dstr);
                            stop = true;
                            break;
                        }
                        if(desc.size() && !desc[0].isEmpty()){
                            name = desc[0];
                        }
                        if(desc.size() > 1){
                            type = desc[1];
                        }
                        if(desc.size() > 2){
                            size = desc[2].toUint(10);
                        }
                    }

                    if(ptr){
                        LOG("Data Pointer 0x" << ZString::ItoS(addr, 16) << ": " << name);
                        if(type == ".word"){
                            model->addDataPointer(addr, name, size);
                        } else {
                            model->addDataPointer(addr, name);
                        }
                    } else {
                        LOG("Data 0x" << ZString::ItoS(addr, 16) << ": " << name);
                        if(type == ".word"){
                            model->addData(addr, name, size);
                        } else {
                            model->addData(addr, name);
                        }
                    }
                    if(force){
                        model->setForced(addr, ImageModel::DATA);
                    }
                }
                break;
            }

            case SEC_ANNOTE: {
                ArZ line = lines[i].explode(':');
                if(line.size()){
                    if(line[0].isEmpty())
                        break;

                    ZString adr = line[0];
                    adr.strip('\r').strip(' ').strip('\t').strip(' ');
                    zu64 addr;
                    if(adr.beginsWith("+")){
                        zu64 tmp = adr.substr(1).toUint(16);
                        if(tmp == ZU64_MAX){
                            LOG(file << ": bad offset");
                            stop = true;
                            break;
                        }
                        addr = prevaddr + tmp;
                    } else {
                        addr = adr.toUint(16);
                        if(addr == ZU64_MAX){
                            LOG(file << ": bad offset");
                            stop = true;
                            break;
                        }
                    }
                    prevaddr = addr;

                    ZString note = line[1];
                    note.strip('\r').strip(' ').strip('\t').strip(' ');

                    model->addAnnotation(addr, note);
                }
                break;
            }

            default:
                ELOG("No section defined!");
                stop = true;
        }

        if(stop)
            break;
    }

    return total;
}

int main(int argc, char **argv){
    ZLog::logLevelStdOut(ZLog::INFO, "%clock% N %log%");
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
            bool offsets = opts.contains(OPT_OFFSETS);
            bool annotate = opts.contains(OPT_ANNOTATE);

            if(verbose){
                ZLog::logLevelStdOut(ZLog::DEBUG, "%clock% D %log%\x1b[m");
            }

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
                    total += parseSymbolFile(it.get(), &model);
                }
            }

            LOG("Total Instructions: " << total);

            ZBinary code = model.makeCode(offsets, annotate);
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
                "    [-AEOV] [-a image_vma]" << ZLog::NEWLN <<
                "    [-s symbol_address_file]" << ZLog::NEWLN);
            return 1;
        }

    } catch(ZException ex){
        ELOG("Exception: " << ex.what());
    }

    return 0;
}

