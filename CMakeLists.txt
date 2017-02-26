CMAKE_MINIMUM_REQUIRED(VERSION 2.8)
PROJECT(ReAssemble)

ADD_SUBDIRECTORY(libchaos)
ADD_SUBDIRECTORY(capstone)

SET(SOURCES
    main.cpp
    imagemodel.h
    imagemodel.cpp
    imageelement.h
    imageelement.cpp
)

SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g")

ADD_EXECUTABLE(reassemble ${SOURCES})

LibChaos_Configure_Target(reassemble)
TARGET_LINK_LIBRARIES(reassemble capstone-static)

SET(FILES
    reas.sh
    vma.ld
    example/firmware_v117.bin
    example/firmware_v117.txt
    example/symbols_v117.txt
    example/firmware_builtin.bin
    example/firmware_builtin.txt
)
ADD_CUSTOM_TARGET(reassemble-dummy SOURCES ${FILES})
