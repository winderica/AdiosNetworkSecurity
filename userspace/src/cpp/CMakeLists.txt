cmake_minimum_required(VERSION 3.9)
cmake_policy(SET CMP0042 NEW)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_JS_INC "/usr/include/node")
set(NODE_ADDON_API_DIR "../../node_modules/node-addon-api")

project(firewall-addon)

include_directories(${CMAKE_JS_INC})

file(GLOB SOURCE_FILES "src/*.cc")

add_library(${PROJECT_NAME} SHARED ${SOURCE_FILES})
set_target_properties(${PROJECT_NAME} PROPERTIES PREFIX "" SUFFIX ".node")
target_include_directories(${PROJECT_NAME} PRIVATE ${NODE_ADDON_API_DIR})

add_definitions(-DNAPI_VERSION=7)