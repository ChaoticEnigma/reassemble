#ifndef IMAGEMODEL_H
#define IMAGEMODEL_H

#include "imageelement.h"

#include "zbinary.h"
#include "zmap.h"
#include "zlist.h"

#include "capstone/include/capstone.h"

using namespace LibChaos;

class ImageModel {
public:
    enum reftype {
        DATA,
        CODE,
        RAW,
    };
    enum codetype {
        NORMAL,
        DBRANCH,
        IBRANCH,
        LOAD,
    };
    enum labeltype {
        NAMED = 0,
        CALL,
        SWITCH,
        JUMP,
        LDATA,
        LNONE,
    };

    struct Label {
        labeltype type;
        ZString str;
    };

    struct RefElem {
        reftype type;
        zu16 size;
        ZString str;

        codetype ctype;
        zu64 target;

        labeltype ltype;
        ZString label;
    };

public:
    ImageModel();
    ~ImageModel();

    //! Load a binary image at the given offset.
    void loadImage(const ZBinary &bin, zu64 offset);
    //! Add a code entry point in the provided binary.
    zu64 addEntry(zu64 addr, ZString name = ZString());

    zu64 disassembleAddress(zu64 addr, Label label);

    ZBinary makeCode();

public:
    zu64 base;

    ZBinary image;
    ZMap<zu64, RefElem> refs;

    csh handle;
    cs_err err;
};

#endif // IMAGEMODEL_H
