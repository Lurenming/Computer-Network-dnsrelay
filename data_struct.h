// ��ֹͷ�ļ����ظ�����
#pragma once

// ����ͷ�ļ�
#include "header.h"
#include "default.h"
#include "system.h"
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <windows.h>
// ���������ַ��������ڴ洢IP��ַ������
char IPAddr[MAX_SIZE];
char domain[MAX_SIZE];

/* �ֵ����ṹ�� */
typedef struct tree_node {
	uint16_t pre;			// �������
	uint16_t val[37];		// ��ȡ�����е�ÿ���ַ��ı��num����val[num]��Ŷ���ĳ�ַ�ʱ���ý��ı��
	uint8_t IP[4];			// ʮ����IP��ַ
	uint8_t isEnd;			// �Ƿ�Ϊһ�������Ľ���
} tree;

/* LRU����ṹ�� */
typedef struct node {
	uint8_t IP[4];           // IP��ַ
	char domain[MAX_SIZE];   // ����
	int frequency;  // ����Ƶ�ʼ�����
	struct node* next;       // ָ����һ���ڵ��ָ��
} lfu_node;

typedef struct {
	uint16_t client_ID;            // �ͻ���ID
	int expire_time;               // ����ʱ��
	struct sockaddr_in client_addr;// �ͻ��˵�ַ
} ID_conversion;

ID_conversion ID_list[ID_LIST_SIZE]; // IDת����

tree trie[MAX_NUM];    // �洢������Ϣ���ֵ���
lfu_node* head;             // LRU����ͷָ��
lfu_node* tail;             // LRU����βָ��
int list_size;              // �ֵ����ڵ���
int cache_size;             // �����С

/* ��ȡ�ַ�����ʽ��IPv4��ַ��ת������������ */
void transfer_IP(uint8_t* this_IP, char* IP_addr);

/* ���������ַ�ת�ɶ�Ӧ��ֵ */
int get_num(uint8_t val);

/* ���ӡ���ѯ�ֵ������ */
void add_node(uint8_t* IP, char* domain);
int query_node( char* domain, uint8_t* ip_addr);

/* ��ʼ������ */
void init_cache();

/* �ӻ��������в�ѯ */
int query_cache(char* domain, uint8_t* ip_addr);

/* ���»������� */
void update_cache(uint8_t ip_addr[4], char* domain);

/* ɾ����Զδʹ�ý�� */
void delete_cache();

/* ���ÿͻ���ID */
uint16_t set_ID(uint16_t client_ID, struct sockaddr_in client_addr);