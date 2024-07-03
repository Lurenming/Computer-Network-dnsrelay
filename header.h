#pragma once

// 标准输入输出库
#include <stdio.h>

// 标准库，包含内存分配、进程控制、转换等函数
#include <stdlib.h>

// 字符串操作函数库
#include <string.h>

// 标准整数类型定义
#include <stdint.h>

// 包含网络操作函数库（在Unix/Linux系统上使用）
#include <arpa/inet.h>

// Windows平台的网络编程库
#include <WinSock2.h>
#include <ws2tcpip.h>

// 链接WinSock2库（仅在Windows平台上使用）
#pragma comment(lib, "ws2_32.lib")

// 禁用4996号警告，允许使用不安全的函数（仅在Visual Studio上使用）
#pragma warning(disable:4996)
