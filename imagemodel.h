#ifndef IMAGEMODEL_H
#define IMAGEMODEL_H

#include "imageelement.h"

#include "zbinary.h"
#include "zmap.h"
#include "zlist.h"

#include "capstone/capstone.h"

using namespace LibChaos;

class ImageModel {
public:
    ImageModel();
    ~ImageModel();

    //! Load a binary image at the given offset.
    void loadImage(const ZBinary &bin, zu64 offset);
    //! Add a code entry point in the provided binaries.
    zu64 disassAddr(zu64 addr);

    ZBinary makeCode();

public:
    zu64 vma;
    zu64 size;
    ZArray<zu32> vectors;
    ZMap<zu64, ImageElement> map;

    csh handle;
    cs_err err;
};

#endif // IMAGEMODEL_H
