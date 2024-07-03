#include "debug.h"

/* 打印DNS报文头信息 */
void print_header(dns_message* msg) {
    printf("-----------header-----------\n");
    printf("ID = %d, ", msg->header->id);
    printf("qr = %d, ", msg->header->qr);
    printf("opcode = %d, ", msg->header->opcode);
    printf("aa = %d, ", msg->header->aa);
    printf("tc = %d, ", msg->header->tc);
    printf("rd = %d, ", msg->header->rd);
    printf("ra = %d, ", msg->header->ra);
    printf("rcode = %d, ", msg->header->rcode);
    printf("qdCount = %d, ", msg->header->qdCount);
    printf("anCount = %d, ", msg->header->anCount);
    printf("nsCount = %d, ", msg->header->nsCount);
    printf("arCount = %d\n", msg->header->arCount);
}

/* 打印DNS查询问题信息 */
void print_question(dns_message* msg) {
    dns_question* question = msg->questions;
    printf("-----------question-----------\n");
    while (question != NULL) {
        printf("domain: %s, ", question->q_name);
        printf("query type: %d, ", question->q_type);
        printf("query class: %d\n", question->q_class);
        question = question->next;
    }
}

/* 打印DNS应答信息 */
void print_answer(dns_message* msg) {
    dns_rr* answer = msg->answers;
    printf("-----------answer-----------\n");
    while (answer != NULL) {
        printf("domain: %s, ", answer->name);
        printf("answer type: %d, ", answer->type);
        printf("resource record class: %d, ", answer->rr_class);
        printf("time to live: %d, ", answer->ttl);
        printf("record length: %d, ", answer->rd_length);

        /* 打印资源记录数据 */
        switch (answer->type) {
            case RR_A: {
                printf("A Record: ");
                for (int j = 0; j < 3; j++) {
                    printf("%d.", answer->rd_data.a_record.IP_addr[j]);
                }
                printf("%d", answer->rd_data.a_record.IP_addr[3]);
                break;
            }
            case RR_CNAME: {
                printf("CNAME Record: %s", answer->rd_data.cname_record.name);
                break;
            }
            case RR_SOA: {
                printf("SOA Record: ");
                printf("MName: %s, ", answer->rd_data.soa_record.MName);
                printf("RName: %s, ", answer->rd_data.soa_record.RName);
                printf("serial: %u, ", answer->rd_data.soa_record.serial);
                printf("refresh: %u, ", answer->rd_data.soa_record.refresh);
                printf("retry: %u, ", answer->rd_data.soa_record.retry);
                printf("expire: %u, ", answer->rd_data.soa_record.expire);
                printf("minimum: %u", answer->rd_data.soa_record.minimum);
                break;
            }
            // 可以添加其他资源记录类型的打印信息
            default:
                printf("Unknown Record Type");
                break;
        }
        printf("\n");
        answer = answer->next;
    }
}
