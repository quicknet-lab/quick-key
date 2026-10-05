cmake_minimum_required(VERSION 3.16)

set(PROJECT_VER "1.0.0")

# The secure build (Secure Boot, flash encryption, anti-rollback — all burned
# into eFuses on the first boot) is opt-in and layered on top of
# sdkconfig.defaults:
#   idf.py -B build-secure -D QUICK_KEY_SECURE=1 build
# It keeps its sdkconfig inside its own build directory: the project-level
# sdkconfig overrides the defaults files, so letting the secure build write
# there would quietly turn the next ordinary build into one that burns eFuses.
option(QUICK_KEY_SECURE "Build with Secure Boot, flash encryption and anti-rollback" OFF)
set(SDKCONFIG_DEFAULTS "${CMAKE_CURRENT_LIST_DIR}/sdkconfig.defaults")
if(QUICK_KEY_SECURE)
    list(APPEND SDKCONFIG_DEFAULTS "${CMAKE_CURRENT_LIST_DIR}/sdkconfig.secure")
    set(SDKCONFIG "${CMAKE_BINARY_DIR}/sdkconfig")
else()
    # An ordinary build refuses an sdkconfig with an eFuse-burning option.
    set(_sdkconfig "${CMAKE_CURRENT_LIST_DIR}/sdkconfig")
    if(SDKCONFIG)
        set(_sdkconfig "${SDKCONFIG}")
    endif()
    if(EXISTS "${_sdkconfig}")
        file(STRINGS "${_sdkconfig}" _burning REGEX
             "^CONFIG_(SECURE_BOOT|SECURE_FLASH_ENC_ENABLED|BOOTLOADER_APP_ANTI_ROLLBACK)=y$")
        if(_burning)
            message(FATAL_ERROR
                "${_sdkconfig} enables eFuse-burning options (${_burning}) in an "
                "ordinary build. Delete it and build again; the secure build is "
                "-D QUICK_KEY_SECURE=1 in a build directory of its own.")
        endif()
    endif()
endif()

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(quick-key)
