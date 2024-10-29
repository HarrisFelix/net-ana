cmake_minimum_required(VERSION 3.10)
project(analyzer C)

# Enable export of compile commands
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Include directory for public headers
include_directories(include)

# Find all .c files in src/ and add them to the project
file(GLOB SOURCES "src/*.c")

# Create the executable from the source files
add_executable(analyzer ${SOURCES})

# Link the pcap library
target_link_libraries(analyzer pcap)

# Custom target for testing
add_custom_target(test
    COMMAND ./analyzer -i en0 -v 1
    DEPENDS analyzer
)
