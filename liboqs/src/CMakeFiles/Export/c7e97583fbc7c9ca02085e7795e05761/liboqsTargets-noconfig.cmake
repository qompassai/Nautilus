#----------------------------------------------------------------
# Generated CMake target import file.
#----------------------------------------------------------------

# Commands may need to know the format version.
set(CMAKE_IMPORT_FILE_VERSION 1)

# Import target "OQS::oqs" for configuration ""
set_property(TARGET OQS::oqs APPEND PROPERTY IMPORTED_CONFIGURATIONS NOCONFIG)
set_target_properties(OQS::oqs PROPERTIES
  IMPORTED_LOCATION_NOCONFIG "${_IMPORT_PREFIX}/lib/liboqs.so.0.10.2-dev"
  IMPORTED_SONAME_NOCONFIG "liboqs.so.5"
  )

list(APPEND _cmake_import_check_targets OQS::oqs )
list(APPEND _cmake_import_check_files_for_OQS::oqs "${_IMPORT_PREFIX}/lib/liboqs.so.0.10.2-dev" )

# Commands beyond this point should not need to know the version.
set(CMAKE_IMPORT_FILE_VERSION)
