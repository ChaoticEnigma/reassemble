#ifndef IMAGEELEMENT_H
#define IMAGEELEMENT_H

#include "zbinary.h"

using namespace LibChaos;

class ImageElement {
public:
    enum elemtype {
        DATA,
        CODE,
    };
public:
    ImageElement();

private:
    elemtype type;
    ZBinary data;
};

#endif // IMAGEELEMENT_H
