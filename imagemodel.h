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

    struct RefElem {
        reftype type;
        codetype ctype;
        zu16 size;
        ZString str;
        ZString label;
        zu64 target;
    };

public:
    ImageModel();
    ~ImageModel();

    //! Load a binary image at the given offset.
    void loadImage(const ZBinary &bin, zu64 offset);
    //! Add a code entry point in the provided binary.
    zu64 disassAddr(zu64 addr, ZString name = ZString());

    ZBinary makeCode();

public:
    zu64 base;

    ZBinary image;
    ZMap<zu64, RefElem> refs;

    csh handle;
    cs_err err;
};

#endif // IMAGEMODEL_H
