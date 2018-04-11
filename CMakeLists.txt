CMAKE_MINIMUM_REQUIRED(VERSION 2.8)
PROJECT(ReAssemble)

ADD_SUBDIRECTORY(libchaos)

LIST(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}")
FIND_PACKAGE(Capstone REQUIRED)

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
TARGET_INCLUDE_DIRECTORIES(reassemble PRIVATE "${CAPSTONE_INCLUDE_DIRS}")
TARGET_LINK_LIBRARIES(reassemble chaos "${CAPSTONE_LIBRARIES}")
SET_PROPERTY(TARGET reassemble PROPERTY CXX_STANDARD 11)

INSTALL(TARGETS reassemble RUNTIME DESTINATION bin)

SET(FILES
    README.md
    reas.sh
    example/firmware_v117.bin
    example/symbols_v117.txt
    example/data_v117.txt
    example/vma.ld
)
ADD_CUSTOM_TARGET(reassemble-dummy SOURCES ${FILES})
