#pragma once

#include "dns_struct.h"

/* 打印DNS报文头信息 */
void print_header(dns_message* msg);

/* 打印DNS查询问题信息 */
void print_question(dns_message* msg);

/* 打印DNS应答信息 */
void print_answer(dns_message* msg);
