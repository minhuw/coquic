cmake_minimum_required(VERSION 3.20)
project(mvfst_perf LANGUAGES CXX)

find_package(glog CONFIG REQUIRED)
find_package(gflags CONFIG REQUIRED)
find_package(mvfst CONFIG REQUIRED)
find_package(folly CONFIG REQUIRED)
find_package(Fizz CONFIG REQUIRED)

add_executable(mvfst-perf mvfst-perf.cpp)
target_compile_features(mvfst-perf PRIVATE cxx_std_20)
target_link_libraries(mvfst-perf PRIVATE ${mvfst_LIBRARIES} fizz::fizz Folly::folly)

install(TARGETS mvfst-perf RUNTIME DESTINATION bin)
