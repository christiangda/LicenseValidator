cmake_minimum_required(VERSION 3.25)

# specify the C++ standard
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED True)
# set(CMAKE_CXX_COMPILE_FEATURES cxx_std_23)
# set(CMAKE_CXX_FLAGS_INIT           "-Wall -std=c++23")
set(CMAKE_CXX_COMPILER             "/usr/bin/clang++")
# set(CMAKE_CXX_FLAGS                "-pedantic -Wextra -Werror -Wno-unused-parameter -Wno-unused-variable -Wunused-but-set-variable -Wno-unused-function -Wno-unused-private-field")
set(CMAKE_CXX_FLAGS                "-Wextra -Wno-unused-parameter -Wno-unused-variable -Wunused-but-set-variable -Wno-unused-function -Wno-unused-private-field")
set(CMAKE_CXX_FLAGS_DEBUG          "-g")
set(CMAKE_CXX_FLAGS_MINSIZEREL     "-Os -DNDEBUG")
set(CMAKE_CXX_FLAGS_RELEASE        "-O3 -DNDEBUG")
set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "-O2 -g")

project(LicenseValidator
      VERSION 0.0.0
      DESCRIPTION "This is a license validator based on the public key"
      LANGUAGES C CXX
)

# add version number to the source code
configure_file(src/Config.h.in Config.h)
include_directories("${PROJECT_BINARY_DIR}")

# Add Boost (brew install boost first)
set(Boost_USE_STATIC_LIBS OFF)
set(Boost_USE_MULTITHREADED ON)
set(Boost_USE_STATIC_RUNTIME OFF)
find_package(Boost 1.85.0 REQUIRED
            COMPONENTS
                program_options
            REQUIRED
)
include_directories(${Boost_INCLUDE_DIRS})

# Openssl
find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

# Add the executable
add_executable("${PROJECT_NAME}"
                src/main.cpp

                src/License.h
                src/License.cpp

                src/Utils.h
                src/Utils.cpp
)

# Link the executable to the depthai-core library
target_link_libraries("${PROJECT_NAME}"
              PUBLIC
                "${Boost_LIBRARIES}"
                "${OPENSSL_LIBRARIES}"
)
