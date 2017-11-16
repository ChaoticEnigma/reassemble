CMAKE_MINIMUM_REQUIRED(VERSION 2.8)
PROJECT(ReAssemble)

ADD_SUBDIRECTORY(libchaos)
ADD_SUBDIRECTORY(capstone)

SET(SOURCES
    main.cpp
    codeblock.h
    codeblock.cpp
    imagemodel.h
    imagemodel.cpp
    imageelement.h
    imageelement.cpp
)

ADD_EXECUTABLE(reassemble ${SOURCES})
TARGET_LINK_LIBRARIES(reassemble chaos capstone-static)

SET(FILES
    README.md
    reas.sh
    vma.ld
    example/firmware_v117.bin
    example/symbols_v117.txt
    example/data_v117.txt
)
ADD_CUSTOM_TARGET(reassemble-dummy SOURCES ${FILES})
