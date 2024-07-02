#include "data_struct.h"  // 包含自定义的数据结构和函数原型

ID_conversion ID_list[ID_LIST_SIZE];  // 定义一个ID_conversion类型的数组，用于存储ID转换信息

tree trie[MAX_NUM];  // 定义一个tree类型的数组，用于存储域名和IP的映射关系
int trie_size = 0;  // 初始化tree列表的大小为0
int cache_size = 0;  // 初始化缓存的大小为0

lfu_node* head;  // 定义LFU链表的头节点
lfu_node* tail;  // 定义LFU链表的尾节点

// 将IP地址字符串转换为4字节的uint8_t数组表示
void transfer_IP(uint8_t* this_IP, char* IP_addr) {
    if (inet_pton(AF_INET, IP_addr, this_IP) != 1) {
        fprintf(stderr, "IP 地址格式无效\n");
    }
}

// 将字符转换为对应的数字
int get_num(uint8_t val) {
    if (val >= '0' && val <= '9') {
        return val - '0';  // 数字0~9
    }
    if (val >= 'a' && val <= 'z') {
        return val - 'a' + 10;  // 字母a~z
    }
    if (val >= 'A' && val <= 'Z') {
        return val - 'A' + 10;  // 字母A~Z
    }
    if (val == '-') {
        return 36;  // 连词号'-'
    }
    if (val == '.') {
        return 37;  // 点号'.'
    }
    return 0;  
}


// 在tree树中添加一个节点
void add_node(uint8_t* IP, char* domain) {
    int i;
    int len = strlen(domain);  // 获取域名的长度
    int index = 0;  // tree树的当前索引

    // 遍历域名字符，将其插入到tree树中
    for (i = 0; i < len; i++) {
        int num = get_num(domain[i]);  // 获取字符对应的数字

        if (trie[index].val[num] == 0) {
            trie[index].val[num] = ++trie_size;  // 分配新节点
        }
        trie[trie[index].val[num]].pre = index;  // 设置前驱节点
        index = trie[index].val[num];  // 更新索引
    }

    // 将IP地址存储到tree节点中
    for (i = 0; i < 4; i++) {
        trie[index].IP[i] = IP[i];
    }

    trie[index].isEnd = 1;  // 标记节点为结束节点
}

// 在tree树中查询一个节点
int query_node(char* domain, uint8_t* ip_addr) {
    int i;
    int len = strlen(domain);  // 获取域名的长度
    int index = 0;  // tree树的当前索引

    // 遍历域名字符，在tree树中查找对应节点
    for (i = 0; i < len; i++) {
        int num = get_num(domain[i]);  // 获取字符对应的数字

        if (trie[index].val[num] == 0) {
            if (debug_mode == 1) {
                printf("Address not found in hosts.\n");  // 调试模式下打印信息
            }
            return 0;
        }

        index = trie[index].val[num];  // 更新索引
    }

    if (trie[index].isEnd == 0) {
        if (debug_mode == 1) {
            printf("Address not found in hosts.\n");  // 调试模式下打印信息
        }
        return 0;
    }

    if (debug_mode == 1) {
        printf("Address found in hosts: ");
        for (i = 0; i < 3; i++) {
            printf("%d.", trie[index].IP[i]);  // 打印找到的IP地址
        }
        printf("%d\n", trie[index].IP[3]);
    }

    update_cache(trie[index].IP, domain);  // 更新缓存
    memcpy(ip_addr, trie[index].IP, 4);  // 将IP地址复制到输出参数中

    return 1;
}

// 初始化ID列表
void init_ID_list() {
    for (int i = 0; i < ID_LIST_SIZE; i++) {
        ID_list[i].client_ID = 0;  // 初始化client_ID为0
        ID_list[i].expire_time = 0;  // 初始化过期时间为0
        memset(&(ID_list[i].client_addr), 0, sizeof(struct sockaddr_in));  // 清零client_addr
    }
}

// 初始化缓存
void init_cache() {
    /* 初始化LFU链表 */
    head = malloc(sizeof(lfu_node));  // 分配头节点
    head->next = NULL;  // 初始化头节点的next指针
    tail = head;  // 初始化尾节点为头节点
}

// 查询缓存中是否存在指定域名
int query_cache(char* domain, uint8_t* ip_addr) {
    lfu_node* ptr = head;

    // 遍历LFU链表，查找是否存在域名
    while (ptr->next) {
        if (strcmp(ptr->next->domain, domain) == 0) { // 相等返回0
            if (debug_mode == 1) {
                printf("Address found in cache: ");
                printf("%d %d %d %d\n", ptr->next->IP[0], ptr->next->IP[1], ptr->next->IP[2], ptr->next->IP[3]);  // 调试模式下打印信息
            }

            memcpy(ip_addr, ptr->next->IP, sizeof(ptr->next->IP));  // 将IP地址复制到输出参数中
            ptr->next->frequency++;  // 增加访问频率
            return 1;
        }
        else {
            ptr = ptr->next;  // 继续查找下一个节点
        }
    }
    return 0;
}

// 更新缓存
void update_cache(uint8_t ip_addr[4], char* domain) {
    lfu_node* newNode = malloc(sizeof(lfu_node));  // 分配新节点

    if (cache_size >= MAX_CACHE) {
        delete_cache();  // 如果缓存超过最大值，则删除访问频率最低的节点
    }

    cache_size++;  // 增加缓存大小

    memcpy(newNode->IP, ip_addr, sizeof(uint8_t) * 4);  // 复制IP地址
    memcpy(newNode->domain, domain, strlen(domain) + 1);  // 复制域名
    newNode->frequency = 1;  // 初始化访问频率为1
    newNode->next = head->next;  // 将新节点插入到头部
    head->next = newNode;
}

// 删除缓存中的访问频率最低的节点
void delete_cache() {
    lfu_node* p = head;
    lfu_node* min_prev = head;
    lfu_node* min_node = head->next;

    // 查找访问频率最低的节点
    while (p->next) {
        if (p->next->frequency < min_node->frequency) {
            min_prev = p;
            min_node = p->next;
        }
        p = p->next;
    }

    // 删除访问频率最低的节点
    if (min_node) {
        min_prev->next = min_node->next;
        free(min_node);
        cache_size--;
    }
}

// 设置ID
uint16_t set_ID(uint16_t client_ID, struct sockaddr_in client_addr) {
    uint16_t i;
    for (i = 0; i < ID_LIST_SIZE; i++) {
        if (ID_list[i].expire_time < time(NULL)) {  // 找到过期的ID
            ID_list[i].client_ID = client_ID;  // 设置client_ID
            ID_list[i].client_addr = client_addr;  // 设置client_addr
            ID_list[i].expire_time = ID_EXPIRE_TIME + time(NULL);  // 设置新的过期时间
        }
        break;
    }
    return i;  // 返回索引
}
