#pragma once

/* 定义一些常量以便在程序中使用 */

/* 字典树的最大结点数 */
#define MAX_NUM 65535

/* 域名的最大长度 */
#define MAX_SIZE 300

/* 缓存的最大容量 */
#define MAX_CACHE 100

/* 监听端口号（DNS使用端口53） */
#define PORT 53

/* DNS报文的最大尺寸 */
#define BUFFER_SIZE 1500

/* ID映射表的大小 */
#define ID_LIST_SIZE 128

/* ID过期时间（单位：秒） */
#define ID_EXPIRE_TIME 4

/* Resource Record（RR）类型定义 */
#define RR_A 1        // A记录（IPv4地址）
#define RR_CNAME 5    // CNAME记录（规范名称）
#define RR_SOA 6      // SOA记录（起始授权机构）
#define RR_PTR 12     // PTR记录（逆向DNS查找）
#define RR_MX 15      // MX记录（邮件交换记录）
#define RR_TXT 16     // TXT记录（文本记录）
#define RR_AAAA 28    // AAAA记录（IPv6地址）
