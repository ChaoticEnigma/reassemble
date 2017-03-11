#ifndef IMAGEMODEL_H
#define IMAGEMODEL_H

#include "imageelement.h"

#include "zbinary.h"
#include "zmap.h"
#include "zlist.h"

#include "capstone/include/capstone.h"

#define HEX(A) (ZString::ItoS((zu64)(A), 16))
//#define HEX(A) (ZString("0x")+ZString::ItoS((A), 16))

using namespace LibChaos;

class ImageModel {
public:
    struct Label {
        ImageElement::labeltype type;
        ZString str;
    };

public:
    ImageModel();
    ~ImageModel();

    //! Load a binary image at the given offset.
    void loadImage(const ZBinary &bin, zu64 offset);
    //! Add a code entry point in the provided binary.
    zu64 addEntry(zu64 addr, ZString name = ZString());
    zu64 addCodePointer(zu64 addr, ZString name = ZString());

    zu64 addData(zu64 addr, ZString name = ZString());
    zu64 addDataPointer(zu64 addr, ZString name = ZString());

    zu64 disassembleAddress(zu64 addr, Label label);

    ZBinary makeCode();

private:
    zu64 _addrToOffset(zu64 addr) const;
    zu64 _offsetToAddr(zu64 offset) const;

public:
    zu64 base;

    ZBinary image;
    ZMap<zu64, ImageElement> refs;

    csh handle;
    cs_err err;
};

#endif // IMAGEMODEL_H
