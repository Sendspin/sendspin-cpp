# Build-only ESP-IDF project that compiles and links the sendspin-cpp component (see README.md)
cmake_minimum_required(VERSION 3.16)
include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(sendspin_esp_idf)
