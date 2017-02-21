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
    ImageModel();
    ~ImageModel();

    //! Load a binary image at the given offset.
    void loadImage(const ZBinary &bin, zu64 offset);
    //! Add a code entry point in the provided binary.
    zu64 disassAddr(zu64 addr);

    ZBinary makeCode();

public:
    zu64 base;
    ZBinary image;

    ZArray<ZPointer<ImageElement>> chunks;
    ZMap<zu64, ZPointer<ImageElement>> code;

    csh handle;
    cs_err err;
};

#endif // IMAGEMODEL_H
