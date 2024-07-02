#include "data_struct.h"  // �����Զ�������ݽṹ�ͺ���ԭ��

ID_conversion ID_list[ID_LIST_SIZE];  // ����һ��ID_conversion���͵����飬���ڴ洢IDת����Ϣ

tree trie[MAX_NUM];  // ����һ��tree���͵����飬���ڴ洢������IP��ӳ���ϵ
int trie_size = 0;  // ��ʼ��tree�б�Ĵ�СΪ0
int cache_size = 0;  // ��ʼ������Ĵ�СΪ0

lfu_node* head;  // ����LFU�����ͷ�ڵ�
lfu_node* tail;  // ����LFU�����β�ڵ�

// ��IP��ַ�ַ���ת��Ϊ4�ֽڵ�uint8_t�����ʾ
void transfer_IP(uint8_t* this_IP, char* IP_addr) {
    if (inet_pton(AF_INET, IP_addr, this_IP) != 1) {
        fprintf(stderr, "IP ��ַ��ʽ��Ч\n");
    }
}

// ���ַ�ת��Ϊ��Ӧ������
int get_num(uint8_t val) {
    if (val >= '0' && val <= '9') {
        return val - '0';  // ����0~9
    }
    if (val >= 'a' && val <= 'z') {
        return val - 'a' + 10;  // ��ĸa~z
    }
    if (val >= 'A' && val <= 'Z') {
        return val - 'A' + 10;  // ��ĸA~Z
    }
    if (val == '-') {
        return 36;  // ���ʺ�'-'
    }
    if (val == '.') {
        return 37;  // ���'.'
    }
    return 0;  
}


// ��tree�������һ���ڵ�
void add_node(uint8_t* IP, char* domain) {
    int i;
    int len = strlen(domain);  // ��ȡ�����ĳ���
    int index = 0;  // tree���ĵ�ǰ����

    // ���������ַ���������뵽tree����
    for (i = 0; i < len; i++) {
        int num = get_num(domain[i]);  // ��ȡ�ַ���Ӧ������

        if (trie[index].val[num] == 0) {
            trie[index].val[num] = ++trie_size;  // �����½ڵ�
        }
        trie[trie[index].val[num]].pre = index;  // ����ǰ���ڵ�
        index = trie[index].val[num];  // ��������
    }

    // ��IP��ַ�洢��tree�ڵ���
    for (i = 0; i < 4; i++) {
        trie[index].IP[i] = IP[i];
    }

    trie[index].isEnd = 1;  // ��ǽڵ�Ϊ�����ڵ�
}

// ��tree���в�ѯһ���ڵ�
int query_node(char* domain, uint8_t* ip_addr) {
    int i;
    int len = strlen(domain);  // ��ȡ�����ĳ���
    int index = 0;  // tree���ĵ�ǰ����

    // ���������ַ�����tree���в��Ҷ�Ӧ�ڵ�
    for (i = 0; i < len; i++) {
        int num = get_num(domain[i]);  // ��ȡ�ַ���Ӧ������

        if (trie[index].val[num] == 0) {
            if (debug_mode == 1) {
                printf("Address not found in hosts.\n");  // ����ģʽ�´�ӡ��Ϣ
            }
            return 0;
        }

        index = trie[index].val[num];  // ��������
    }

    if (trie[index].isEnd == 0) {
        if (debug_mode == 1) {
            printf("Address not found in hosts.\n");  // ����ģʽ�´�ӡ��Ϣ
        }
        return 0;
    }

    if (debug_mode == 1) {
        printf("Address found in hosts: ");
        for (i = 0; i < 3; i++) {
            printf("%d.", trie[index].IP[i]);  // ��ӡ�ҵ���IP��ַ
        }
        printf("%d\n", trie[index].IP[3]);
    }

    update_cache(trie[index].IP, domain);  // ���»���
    memcpy(ip_addr, trie[index].IP, 4);  // ��IP��ַ���Ƶ����������

    return 1;
}

// ��ʼ��ID�б�
void init_ID_list() {
    for (int i = 0; i < ID_LIST_SIZE; i++) {
        ID_list[i].client_ID = 0;  // ��ʼ��client_IDΪ0
        ID_list[i].expire_time = 0;  // ��ʼ������ʱ��Ϊ0
        memset(&(ID_list[i].client_addr), 0, sizeof(struct sockaddr_in));  // ����client_addr
    }
}

// ��ʼ������
void init_cache() {
    /* ��ʼ��LFU���� */
    head = malloc(sizeof(lfu_node));  // ����ͷ�ڵ�
    head->next = NULL;  // ��ʼ��ͷ�ڵ��nextָ��
    tail = head;  // ��ʼ��β�ڵ�Ϊͷ�ڵ�
}

// ��ѯ�������Ƿ����ָ������
int query_cache(char* domain, uint8_t* ip_addr) {
    lfu_node* ptr = head;

    // ����LFU���������Ƿ��������
    while (ptr->next) {
        if (strcmp(ptr->next->domain, domain) == 0) { // ��ȷ���0
            if (debug_mode == 1) {
                printf("Address found in cache: ");
                printf("%d %d %d %d\n", ptr->next->IP[0], ptr->next->IP[1], ptr->next->IP[2], ptr->next->IP[3]);  // ����ģʽ�´�ӡ��Ϣ
            }

            memcpy(ip_addr, ptr->next->IP, sizeof(ptr->next->IP));  // ��IP��ַ���Ƶ����������
            ptr->next->frequency++;  // ���ӷ���Ƶ��
            return 1;
        }
        else {
            ptr = ptr->next;  // ����������һ���ڵ�
        }
    }
    return 0;
}

// ���»���
void update_cache(uint8_t ip_addr[4], char* domain) {
    lfu_node* newNode = malloc(sizeof(lfu_node));  // �����½ڵ�

    if (cache_size >= MAX_CACHE) {
        delete_cache();  // ������泬�����ֵ����ɾ������Ƶ����͵Ľڵ�
    }

    cache_size++;  // ���ӻ����С

    memcpy(newNode->IP, ip_addr, sizeof(uint8_t) * 4);  // ����IP��ַ
    memcpy(newNode->domain, domain, strlen(domain) + 1);  // ��������
    newNode->frequency = 1;  // ��ʼ������Ƶ��Ϊ1
    newNode->next = head->next;  // ���½ڵ���뵽ͷ��
    head->next = newNode;
}

// ɾ�������еķ���Ƶ����͵Ľڵ�
void delete_cache() {
    lfu_node* p = head;
    lfu_node* min_prev = head;
    lfu_node* min_node = head->next;

    // ���ҷ���Ƶ����͵Ľڵ�
    while (p->next) {
        if (p->next->frequency < min_node->frequency) {
            min_prev = p;
            min_node = p->next;
        }
        p = p->next;
    }

    // ɾ������Ƶ����͵Ľڵ�
    if (min_node) {
        min_prev->next = min_node->next;
        free(min_node);
        cache_size--;
    }
}

// ����ID
uint16_t set_ID(uint16_t client_ID, struct sockaddr_in client_addr) {
    uint16_t i;
    for (i = 0; i < ID_LIST_SIZE; i++) {
        if (ID_list[i].expire_time < time(NULL)) {  // �ҵ����ڵ�ID
            ID_list[i].client_ID = client_ID;  // ����client_ID
            ID_list[i].client_addr = client_addr;  // ����client_addr
            ID_list[i].expire_time = ID_EXPIRE_TIME + time(NULL);  // �����µĹ���ʱ��
        }
        break;
    }
    return i;  // ��������
}
