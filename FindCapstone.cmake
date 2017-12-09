# - Try to find CAPSTONE
# Once done, this will define
#  CAPSTONE_FOUND - system has CAPSTONE
#  CAPSTONE_INCLUDE_DIRS - the CAPSTONE include directories
#  CAPSTONE_LIBRARIES - link these to use CAPSTONE

find_package(PkgConfig)
pkg_check_modules(PC_CAPSTONE capstone)

find_path(CAPSTONE_INCLUDE_DIR
    capstone/capstone.h
    HINTS ${PC_CAPSTONE_INCLUDEDIR} ${PC_CAPSTONE_INCLUDE_DIRS}
    PATH_SUFFIXES capstone
)

find_library(CAPSTONE_LIBRARY
    NAMES capstone
    HINTS ${PC_CAPSTONE_LIBDIR} ${PC_CAPSTONE_LIBRARY_DIRS}
)

include(FindPackageHandleStandardArgs)
# handle the QUIETLY and REQUIRED arguments and set CAPSTONE_FOUND to TRUE
# if all listed variables are TRUE
find_package_handle_standard_args(Capstone DEFAULT_MSG
                                  CAPSTONE_LIBRARY CAPSTONE_INCLUDE_DIR)

mark_as_advanced(CAPSTONE_INCLUDE_DIR CAPSTONE_LIBRARY)

set(CAPSTONE_LIBRARIES      ${CAPSTONE_LIBRARY})
set(CAPSTONE_INCLUDE_DIRS   ${CAPSTONE_INCLUDE_DIR})
