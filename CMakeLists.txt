PROJECT("1m-block")

SET( CMAKE_BUILD_TYPE Debug ) 

ADD_EXECUTABLE(1m-block.out main.cpp mylibnet.h pch.h)

target_link_libraries(1m-block.out netfilter_queue)