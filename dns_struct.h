#pragma once

#include "header.h"
#include "default.h"
#include "system.h"

/*
    本头文件专门用于存放DNS报文结构体Message的定义，以及一切有关DNS报文的操作
    DNS 报文格式如下：
    +---------------------+
    |        Header       | 报文头，固定12字节，由结构体DNS_header存储
    +---------------------+
    |       Question      | 向域名服务器的查询请求，由结构体DNS_question存储
    +---------------------+
    |        Answer       | 对于查询问题的回复
    +---------------------+
    |      Authority      | 指向授权域名服务器
    +---------------------+
    |      Additional     | 附加信息
    +---------------------+
    后面三个部分由结构体DNS_resource_record存储
*/

/* DNS 报文结构体 */
typedef struct DNS_message {
    struct DNS_header* header;                 // DNS 报文头
    struct DNS_question* questions;            // 查询请求
    struct DNS_resource_record* answers;       // 查询回复
    struct DNS_resource_record* authorities;   // 授权域名服务器
    struct DNS_resource_record* additionals;   // 附加信息
} dns_message;

/* DNS 报文头结构体 */
typedef struct DNS_header {
    uint16_t id; // 标识符，一对DNS查询和恢复的ID相同 

    /* 以下变量占用空间大小仅为几个比特，故定义位域，压缩空间以高效利用内存 */
    uint8_t qr : 1;     // 0 查询 1 回复
    uint8_t opcode : 4; // 0 标准查询 1 反向查询 2 服务器状态请求
    uint8_t aa : 1;     // 授权回答：如果为1，表示回复的Question部分查询的域名服务器是权威服务器 
    uint8_t tc : 1;     // 截断：如果为1，表示这条消息由于信道的限制而被截断 
    uint8_t rd : 1;     // 期望递归：如果为1，表示期望域名服务器递归查询这个请求
    uint8_t ra : 1;     // 可用递归：如果为1，表示递归查询在域名服务器总有效
    uint8_t z : 3;      // 预留字段
    uint8_t rcode : 4;  // 返回码 0 无差错 1 格式错误 2 服务器错误 3 名字错误 4 无实现 5 拒绝 6 - 15 保留

    /* 以下变量大小均为16位 */
    uint16_t qdCount; // 问题数（通常是1）
    uint16_t anCount; // 回答数
    uint16_t nsCount; // 授权数
    uint16_t arCount; // 附加数
} dns_header;

/* DNS 查询结构体 */
typedef struct DNS_question {
    char* q_name;              // 域名或IP地址
    uint16_t q_type;           // 资源类型
    uint16_t q_class;          // 地址类型，通常为1
    struct DNS_question* next; // 指向下一个查询问题的指针
} dns_question;

/* 资源数据联合体 */
union ResourceData {
    /* IPv4 记录 */
    struct {
        uint8_t IP_addr[4];
    } a_record;

    /* SOA：权威记录的起始 */
    struct {
        char* MName;        // 主服务器域名
        char* RName;        // 管理员邮箱
        uint32_t serial;    // 版本号
        uint32_t refresh;   // 刷新数据间隔
        uint32_t retry;     // 重试间隔
        uint32_t expire;    // 超时重传时间
        uint32_t minimum;   // 默认生存时间
    } soa_record;

    /* CNAME 规范名称记录 */
    struct {
        char* name;
    } cname_record;
};

/* DNS 资源记录结构体 */
typedef struct DNS_resource_record {
    char* name;                  // 域名
    uint16_t type;               // 资源数据类型
    uint16_t rr_class;           // 仅支持1，IN，因特网
    uint32_t ttl;                // 期望此RR被缓存的时间
    uint16_t rd_length;          // RDATA部分的长度
    union ResourceData rd_data;  // 资源内容
    struct DNS_resource_record* next; // 指向下一个资源记录的指针
} dns_rr;

/* 记录结构体，用于其他用途 */
typedef struct record {
    uint8_t addr[16];
    char* txt_data;
} dns_record;

/* 用于获取DNS报文头各值的掩码 */
static const uint32_t QR_MASK = 0x8000;
static const uint32_t OPCODE_MASK = 0x7800;
static const uint32_t AA_MASK = 0x0400;
static const uint32_t TC_MASK = 0x0200;
static const uint32_t RD_MASK = 0x0100;
static const uint32_t RA_MASK = 0x0080;
static const uint32_t RCODE_MASK = 0x000F;

/* 从buffer中读取指定位数的数据 */
size_t get_bits(uint8_t** buffer, int bits);

/* 将指定位数的数据写入buffer */
void set_bits(uint8_t** buffer, int bits, int value);

/* 从buffer中解析域名 */
uint8_t* get_domain(uint8_t* buffer, char* name, uint8_t* start);

/* 将域名写入buffer */
uint8_t* set_domain(uint8_t* buffer, char* name);

/* 解析收到的DNS报文 */
void get_message(dns_message* msg, uint8_t* buffer, uint8_t* start);

/* 组装将要发出的DNS报文 */
uint8_t* set_message(dns_message* msg, uint8_t* buffer, uint8_t* ip_addr);

/* 从buffer中解析DNS报文头 */
uint8_t* get_header(dns_message* msg, uint8_t* buffer);

/* 将DNS报文头写入buffer */
uint8_t* set_header(dns_message* msg, uint8_t* buffer, uint8_t* ip_addr);

/* 从buffer中解析DNS问题部分 */
uint8_t* get_question(dns_message* msg, uint8_t* buffer, uint8_t* start);

/* 将DNS问题部分写入buffer */
uint8_t* set_question(dns_message* msg, uint8_t* buffer);

/* 从buffer中解析DNS答案部分 */
uint8_t* get_answer(dns_message* msg, uint8_t* buffer, uint8_t* start);

/* 将DNS答案部分写入buffer */
uint8_t* set_answer(dns_message* msg, uint8_t* buffer, uint8_t* ip_addr);

/* 释放DNS报文所占用的内存 */
void free_message(dns_message* msg);
