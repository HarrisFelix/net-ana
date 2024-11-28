cmake_minimum_required(VERSION 3.10)
project(analyzer C)

# Enable export of compile commands
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Include directory for public headers
include_directories(include src src/protocols)

# Find all .c files in src/ and add them to the project
file(GLOB_RECURSE SOURCES "src/*.c")

# Set default compile options
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -march=native -O3")

# Create the executable from the source files
add_executable(analyzer ${SOURCES})

# Link the pcap library
target_link_libraries(analyzer pcap)

# Custom target for testing
add_custom_target(test
    COMMAND ./analyzer -i en0 -v 1
    DEPENDS analyzer
)

# Custom target to build a release version and place it in /bin
add_custom_target(release_build ALL
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_SOURCE_DIR}/bin
    COMMAND ${CMAKE_COMMAND} -E env CFLAGS="-O3" ${CMAKE_C_COMPILER} ${SOURCES} -o ${CMAKE_SOURCE_DIR}/bin/analyzer -lpcap
    COMMENT "Building release version of analyzer in /bin"
)
