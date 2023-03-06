cmake_minimum_required(VERSION 3.9.0)

project(fpe_udf)

# 设置 C++ 标准为 C++11
set(CMAKE_CXX_STANDARD 11)

set(CMAKE_BUILD_TYPE Debug)
set(CMAKE_C_FLAGS_DEBUG "-g")
set(CMAKE_CXX_FLAGS_DEBUG "-g")

# 设置编译类型为 Release
set(CMAKE_BUILD_TYPE Release)

# 添加 MySQL 头文件的路径
include_directories(/usr/include/mysql)
include_directories(../include)

# 添加 MySQL 库文件的路径
link_directories(/usr/lib/mysql)

# 添加自己写的库的路径
link_directories(../build/out)

# 添加源文件
add_library(udf SHARED mysql.cpp)

# 链接所需的库文件
target_link_libraries(udf mysqlclient wbcrypto -lgmp -lm)

# 设置生成的库文件名
set_target_properties(udf PROPERTIES PREFIX "")

# 将库文件复制到 MySQL 插件目录中
install(TARGETS udf DESTINATION /usr/lib/mysql/plugin)
