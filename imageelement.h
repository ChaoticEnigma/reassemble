#ifndef IMAGEELEMENT_H
#define IMAGEELEMENT_H

#include "zbinary.h"

using namespace LibChaos;

class ImageElement {
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
    enum fmtype {
        F_STRING,
        F_TARGET,
    };
    enum refflags {
        THUMBFUNC = 1,
    };

public:
    ImageElement();

public:
    reftype type;
    zu16 size;
    ZString str;

    codetype ctype;
    zu64 target;

    fmtype ftype;
    ZString suffix;
};

#endif // IMAGEELEMENT_H
