#include "dns_struct.h"

/* 从buffer中读取指定位数的数据，并转换为主机字节顺序 */
size_t get_bits(uint8_t** buffer, int bits) {
    if (buffer == NULL || *buffer == NULL) {
        fprintf(stderr, "Error: buffer is NULL.\n");
        exit(EXIT_FAILURE);
    }

    /* 根据位数读取数据，并转换为主机字节顺序 */
    if (bits == 8) {
        uint8_t val;
        memcpy(&val, *buffer, 1);
        *buffer += 1;
        return val;
    } else if (bits == 16) {
        uint16_t val;
        memcpy(&val, *buffer, 2);
        *buffer += 2;
        return ntohs(val);
    } else if (bits == 32) {
        uint32_t val;
        memcpy(&val, *buffer, 4);
        *buffer += 4;
        return ntohl(val);
    } else {
        fprintf(stderr, "Error: Unsupported bit size %d. Only 8, 16, and 32 bits are supported.\n", bits);
        exit(EXIT_FAILURE);
    }
}

/* 将指定位数的数据写入buffer，并转换为网络字节顺序 */
void set_bits(uint8_t** buffer, int bits, int value) {
    if (buffer == NULL || *buffer == NULL) {
        fprintf(stderr, "Error: buffer is NULL.\n");
        exit(EXIT_FAILURE);
    }

    /* 根据位数写入数据，并转换为网络字节顺序 */
    if (bits == 8) {
        uint8_t val = (uint8_t)value;
        memcpy(*buffer, &val, 1);
        *buffer += 1;
    } else if (bits == 16) {
        uint16_t val = htons((uint16_t)value);
        memcpy(*buffer, &val, 2);
        *buffer += 2;
    } else if (bits == 32) {
        uint32_t val = htonl((uint32_t)value);
        memcpy(*buffer, &val, 4);
        *buffer += 4;
    } else {
        fprintf(stderr, "Error: Unsupported bit size %d. Only 8, 16, and 32 bits are supported.\n", bits);
        exit(EXIT_FAILURE);
    }
}

/* 从buffer中解析DNS报文头，存入dns_message结构体 */
uint8_t* get_header(dns_message* msg, uint8_t* buffer) {
    if (msg == NULL || buffer == NULL) {
        fprintf(stderr, "Error: msg or buffer is NULL.\n");
        exit(EXIT_FAILURE);
    }

    /* 解析DNS报文头的各个字段 */
    msg->header->id = get_bits(&buffer, 16);

    uint16_t val = get_bits(&buffer, 16);
    msg->header->qr = (val & QR_MASK) >> 15;
    msg->header->opcode = (val & OPCODE_MASK) >> 11;
    msg->header->aa = (val & AA_MASK) >> 10;
    msg->header->tc = (val & TC_MASK) >> 9;
    msg->header->rd = (val & RD_MASK) >> 8;
    msg->header->ra = (val & RA_MASK) >> 7;
    msg->header->rcode = (val & RCODE_MASK);

    msg->header->qdCount = get_bits(&buffer, 16);
    msg->header->anCount = get_bits(&buffer, 16);
    msg->header->nsCount = get_bits(&buffer, 16);
    msg->header->arCount = get_bits(&buffer, 16);

    if (debug_mode == 1) {
        print_header(msg);
    }

    return buffer;
}

/* 将DNS报文头存入buffer，准备发送 */
uint8_t* set_header(dns_message* msg, uint8_t* buffer, uint8_t* ip_addr) {
    if (msg == NULL || buffer == NULL || ip_addr == NULL) {
        fprintf(stderr, "Error: msg, buffer, or ip_addr is NULL.\n");
        exit(EXIT_FAILURE);
    }

    dns_header* header = msg->header;
    header->qr = 1;        // 回答报文
    header->aa = 1;        // 权威域名服务器
    header->ra = 1;        // 可用递归
    header->anCount = 1;   // 1个回复

    /* 若查到0.0.0.0，则该域名被屏蔽 */
    header->rcode = (ip_addr[0] == 0 && ip_addr[1] == 0 && ip_addr[2] == 0 && ip_addr[3] == 0) ? 3 : 0;

    /* 将各个字段写入buffer */
    set_bits(&buffer, 16, header->id);

    int flags = 0;
    flags |= (header->qr << 15) & QR_MASK;
    flags |= (header->opcode << 11) & OPCODE_MASK;
    flags |= (header->aa << 10) & AA_MASK;
    flags |= (header->tc << 9) & TC_MASK;
    flags |= (header->rd << 8) & RD_MASK;
    flags |= (header->ra << 7) & RA_MASK;
    flags |= (header->rcode << 0) & RCODE_MASK;

    set_bits(&buffer, 16, flags);
    set_bits(&buffer, 16, header->qdCount);
    set_bits(&buffer, 16, header->anCount);
    set_bits(&buffer, 16, header->nsCount);
    set_bits(&buffer, 16, header->arCount);

    return buffer;
}

/* 从buffer中解析DNS问题部分，存入dns_message结构体 */
uint8_t* get_question(dns_message* msg, uint8_t* buffer, uint8_t* start) {
    if (msg == NULL || buffer == NULL || start == NULL) {
        fprintf(stderr, "Error: msg, buffer, or start is NULL.\n");
        exit(EXIT_FAILURE);
    }

    int i;
    for (i = 0; i < msg->header->qdCount; i++) {
        char name[MAX_SIZE] = { 0 };
        dns_question* p = malloc(sizeof(dns_question));
        if (p == NULL) {
            fprintf(stderr, "Error: Memory allocation failed for dns_question.\n");
            exit(EXIT_FAILURE);
        }

        /* 从DNS报文中获取查询域名 */
        buffer = get_domain(buffer, name, start);

        p->q_name = malloc(strlen(name) + 1);
        if (p->q_name == NULL) {
            fprintf(stderr, "Error: Memory allocation failed for q_name.\n");
            exit(EXIT_FAILURE);
        }
        memcpy(p->q_name, name, strlen(name) + 1);

        p->q_type = get_bits(&buffer, 16);
        p->q_class = get_bits(&buffer, 16);

        /* 头插法插入结点 */
        p->next = msg->questions;
        msg->questions = p;

        if (debug_mode == 1) {
            print_question(msg);
        }
    }

    return buffer;
}

/* 将DNS问题部分存入buffer，准备发送 */
uint8_t* set_question(dns_message* msg, uint8_t* buffer) {
    if (msg == NULL || buffer == NULL) {
        fprintf(stderr, "Error: msg or buffer is NULL.\n");
        exit(EXIT_FAILURE);
    }

    dns_question* p = msg->questions;
    while (p != NULL) {
        buffer = set_domain(buffer, p->q_name);
        set_bits(&buffer, 16, p->q_type);
        set_bits(&buffer, 16, p->q_class);
        p = p->next;
    }

    return buffer;
}

/* 从buffer中解析DNS答案部分，存入dns_message结构体 */
uint8_t* get_answer(dns_message* msg, uint8_t* buffer, uint8_t* start) {
    if (msg == NULL || buffer == NULL || start == NULL) {
        fprintf(stderr, "Error: msg, buffer, or start is NULL.\n");
        exit(EXIT_FAILURE);
    }

    int i, j;
    for (i = 0; i < msg->header->anCount; i++) {
        char name[MAX_SIZE] = { 0 };
        dns_rr* p = malloc(sizeof(dns_rr));
        if (p == NULL) {
            fprintf(stderr, "Error: Memory allocation failed for dns_rr.\n");
            exit(EXIT_FAILURE);
        }

        /* 从DNS报文中获取查询域名 */
        buffer = get_domain(buffer, name, start);

        p->name = malloc(strlen(name) + 1);
        if (p->name == NULL) {
            fprintf(stderr, "Error: Memory allocation failed for name.\n");
            exit(EXIT_FAILURE);
        }
        memcpy(p->name, name, strlen(name) + 1);

        p->type = get_bits(&buffer, 16);
        p->rr_class = get_bits(&buffer, 16);
        p->ttl = get_bits(&buffer, 32);
        p->rd_length = get_bits(&buffer, 16);

        /* 获取IPv4地址 */
        if (p->type == RR_A) {
            for (j = 0; j < 4; j++) {
                p->rd_data.a_record.IP_addr[j] = get_bits(&buffer, 8);
            }
        } else {
            buffer += p->rd_length;
        }

        /* 头插法插入结点 */
        p->next = msg->answers;
        msg->answers = p;

        if (debug_mode == 1) {
            print_answer(msg);
        }
    }
    return buffer;
}

/* 将DNS答案部分存入buffer，准备发送 */
uint8_t* set_answer(dns_message* msg, uint8_t* buffer, uint8_t* ip_addr) {
    if (msg == NULL || buffer == NULL || ip_addr == NULL) {
        fprintf(stderr, "Error: msg, buffer, or ip_addr is NULL.\n");
        exit(EXIT_FAILURE);
    }

    /* 将查询域名存入buffer */
    buffer = set_domain(buffer, msg->questions->q_name);

    /* 将各个字段写入buffer */
    set_bits(&buffer, 16, 1);    // type
    set_bits(&buffer, 16, 1);    // rr_class
    set_bits(&buffer, 32, 4);    // ttl
    set_bits(&buffer, 16, 4);    // rd_length

    /* 写入IPv4地址 */
    int i;
    for (i = 0; i < 4; i++) {
        *buffer = ip_addr[i];
        buffer++;
    }

    return buffer;
}

/* 从buffer中解析域名 */
uint8_t* get_domain(uint8_t* buffer, char* name, uint8_t* start) {
    if (buffer == NULL || name == NULL || start == NULL) {
        fprintf(stderr, "Error: buffer, name, or start is NULL.\n");
        exit(EXIT_FAILURE);
    }

    uint8_t* ptr = buffer;
    int i = 0, len = 0;

    /* 如果是指针，则获取偏移量，并递归调用 */
    if (*ptr >= 0xc0) {
        uint16_t offset = ((*ptr & 0x3f) << 8) | *(ptr + 1);
        get_domain(start + offset, name, start);
        return buffer + 2;
    }

    /* 循环读取域名 */
    while (1) {
        uint8_t val = *ptr;
        ptr++;

        /* 读到00或指针，则结束读入域名 */
        if (val == 0 || val >= 0xc0) {
            return ptr;
        } else if (len == 0) { /* 若此时待读字符数为0，则开始读入字符 */
            len = val;
            if (i != 0) {
                name[i++] = '.';
            }
        } else {
            name[i++] = val;
            len--;
        }
    }

    /* 如果是指针，则获取偏移量，并递归调用 */
    if (*ptr >= 0xc0) {
        char name2[MAX_SIZE] = { 0 };
        uint16_t offset = ((*ptr & 0x3f) << 8) + *(ptr + 1); // 获取后14位偏移量
        get_domain(start + offset, name2, start);
        strcat(name, name2);
        ptr += 2;
    } else if (*ptr == 0) {
        ptr++;
    }

    return ptr;
}

/* 将域名写入buffer */
uint8_t* set_domain(uint8_t* buffer, char* name) {
    if (buffer == NULL || name == NULL) {
        fprintf(stderr, "Error: buffer or name is NULL.\n");
        exit(EXIT_FAILURE);
    }

    uint8_t* ptr = name;
    char tmp[MAX_SIZE] = { 0 };
    int i = 0;

    /* 循环写入域名 */
    while (1) {
        if (*ptr == 0) {
            *buffer = i;
            buffer++;
            memcpy(buffer, tmp, i);
            buffer += i;

            *buffer = 0;
            buffer++;
            break;
        } else if (*ptr != '.') {
            tmp[i++] = *ptr;
        } else if (*ptr == '.') {
            *buffer = i;
            buffer++;
            memcpy(buffer, tmp, i);
            buffer += i;
            memset(tmp, 0, sizeof(tmp));
            i = 0;
        }
        ptr++;
    }

    return buffer;
}

/* 解析收到的DNS报文 */
void get_message(dns_message* msg, uint8_t* buffer, uint8_t* start) {
    if (msg == NULL || buffer == NULL || start == NULL) {
        fprintf(stderr, "Error: msg, buffer, or start is NULL.\n");
        exit(EXIT_FAILURE);
    }

    /* 分配空间 */
    msg->header = malloc(sizeof(dns_header));
    if (msg->header == NULL) {
        fprintf(stderr, "Error: Memory allocation failed for dns_header.\n");
        exit(EXIT_FAILURE);
    }

    msg->questions = NULL;
    msg->answers = NULL;

    /* 获取报文头 */
    buffer = get_header(msg, buffer);

    /* 获取询问内容 */
    buffer = get_question(msg, buffer, start);

    /* 获取应答内容 */
    buffer = get_answer(msg, buffer, start);
}

/* 组装将要发出的DNS报文 */
uint8_t* set_message(dns_message* msg, uint8_t* buffer, uint8_t* ip_addr) {
    if (msg == NULL || buffer == NULL || ip_addr == NULL) {
        fprintf(stderr, "Error: msg, buffer, or ip_addr is NULL.\n");
        exit(EXIT_FAILURE);
    }

    /* 组装报头 */
    buffer = set_header(msg, buffer, ip_addr);
    /* 组装询问 */
    buffer = set_question(msg, buffer);
    /* 组装回答 */
    buffer = set_answer(msg, buffer, ip_addr);

    return buffer;
}

/* 释放DNS报文所占用的内存 */
void free_message(dns_message* msg) {
    if (msg == NULL) {
        return;
    }

    free(msg->header);

    dns_question* q = msg->questions;
    while (q != NULL) {
        dns_question* tmp = q;
        q = q->next;
        free(tmp->q_name);
        free(tmp);
    }

    dns_rr* a = msg->answers;
    while (a != NULL) {
        dns_rr* tmp = a;
        a = a->next;
        free(tmp->name);
        free(tmp);
    }

    free(msg);
}
