#include <linux/netfilter_ipv4.h>
#include <linux/inetdevice.h>
#include <net/tcp.h>
#include <net/udp.h>
#include "lib/hashmap.h"
#include "lib/vector.h"

uint32_t NETLINK_USER = 31;
uint32_t LAN_IP = 0x02A8C0; // 192.168.2.0
uint32_t LAN_MASK = 0xFFFFFF; // 255.255.255.0
bool REJECT_BY_DEFAULT = true;

typedef struct {
    uint32_t srcIP;
    uint32_t srcMask;
    uint32_t dstIP;
    uint32_t dstMask;
    uint16_t srcPort;
    uint16_t dstPort;
    uint8_t protocol;
    uint8_t action;
    uint8_t log;
    uint32_t start;
    uint32_t end;
} Rule;
typedef struct {
    uint32_t srcIP;
    uint32_t dstIP;
    uint16_t srcPort;
    uint16_t dstPort;
    uint8_t protocol;
    uint64_t expire;
} __attribute__((packed)) Connection;
typedef struct {
    uint32_t lanIP;
    uint16_t lanPort;
    uint16_t wanPort;
} NATEntry;
typedef struct {
    uint32_t srcIP;
    uint32_t dstIP;
    uint16_t srcPort;
    uint16_t dstPort;
    uint8_t protocol;
    uint8_t action;
    uint64_t timestamp;
} Log;

cvector_vector_type(Rule)rules = NULL;
struct hashmap *connections;
cvector_vector_type(Connection)activeConnections = NULL;
cvector_vector_type(Log)logs = NULL;
static NATEntry wanNATEntries[65536];
struct hashmap *lanNATEntries;
cvector_vector_type(NATEntry)activeNATEntries = NULL;
uint16_t natPort = 10000;
struct sock *netlinkSocket = NULL;

/**
 * @brief determine if the given ip is in LAN
 * @param ip
 * @return
 */
inline uint8_t isLAN(uint32_t ip) {
    return (ip & LAN_MASK) == LAN_IP;
}

/**
 * @brief get IP of network device/interface
 * @param dev
 * @return
 */
inline uint32_t deviceIP(const struct net_device *dev) {
    if (!dev || !dev->ip_ptr || !dev->ip_ptr->ifa_list) {
        return 0;
    }
    return dev->ip_ptr->ifa_list->ifa_local;
}

/**
 * @brief update checksum of IP header and TCP/UDP header
 * @param b socket buffer, all variables of `struct sk_buff *` type will be called `b` in the following code
 */
inline void updateChecksum(struct sk_buff *b) {
    uint32_t len = b->len - 4 * ip_hdr(b)->ihl;
    ip_hdr(b)->check = 0;
    ip_hdr(b)->check = ip_fast_csum(ip_hdr(b), ip_hdr(b)->ihl);
    switch (ip_hdr(b)->protocol) {
        case IPPROTO_TCP:
            tcp_hdr(b)->check = 0;
            tcp_hdr(b)->check = tcp_v4_check(len, ip_hdr(b)->saddr, ip_hdr(b)->daddr, csum_partial(tcp_hdr(b), len, 0));
            break;
        case IPPROTO_UDP:
            udp_hdr(b)->check = 0;
            udp_hdr(b)->check = udp_v4_check(len, ip_hdr(b)->saddr, ip_hdr(b)->daddr, csum_partial(udp_hdr(b), len, 0));
            break;
        default:
            break;
    }
}

/**
 * @brief hash function of connections, used by hashmap
 * @param item
 * @param seed0
 * @param seed1
 * @return
 */
uint64_t hashConnection(const void *item, uint64_t seed0, uint64_t seed1) {
    return hashmap_sip(item, sizeof(Connection) - sizeof(uint64_t), seed0, seed1);
}

/**
 * @brief comparator of connections, used by hashmap
 * @param a
 * @param b
 * @param data
 * @return
 */
int compareConnection(const void *a, const void *b, void *data) {
    return memcmp(a, b, sizeof(Connection) - sizeof(uint64_t));
}

/**
 * copy connections from hashmap to active connections vector
 * @param item
 * @param data
 * @return
 */
bool filterConnection(const void *item, void *data) {
    const Connection *connection = item;
    if (ktime_get_real_seconds() < connection->expire) {
        cvector_push_back(activeConnections, *connection);
    }
    return true;
}

/**
 * @brief hash function of NAT entries, used by hashmap
 * @param item
 * @param seed0
 * @param seed1
 * @return
 */
uint64_t hashNATEntry(const void *item, uint64_t seed0, uint64_t seed1) {
    return hashmap_sip(item, sizeof(uint32_t) + sizeof(uint16_t), seed0, seed1);
}

/**
 * @brief comparator of NAT entries, used by hashmap
 * @param a
 * @param b
 * @param data
 * @return
 */
int compareNATEntry(const void *a, const void *b, void *data) {
    return memcmp(a, b, sizeof(uint32_t) + sizeof(uint16_t));
}

/**
 * @brief add NAT entry to WAN NAT table and LAN NAT hashmap
 * @param ip
 * @param port
 * @return
 */
uint16_t addNATEntry(uint32_t ip, uint16_t port) {
    uint16_t wanPort = natPort++;
    if (natPort == 0) {
        natPort = 10000;
    }
    wanNATEntries[wanPort].lanIP = ip;
    wanNATEntries[wanPort].lanPort = port;
    wanNATEntries[wanPort].wanPort = wanPort;
    hashmap_set(lanNATEntries, &wanNATEntries[wanPort]);
    return wanPort;
}

/**
 * @brief copy NAT entries from hashmap to active NAT entries vector
 * @param item
 * @param data
 * @return
 */
bool filterNATEntry(const void *item, void *data) {
    const NATEntry *natEntry = item;
    cvector_push_back(activeNATEntries, *natEntry);
    return true;
}

/**
 * @brief find the corresponding rule in the rules table
 * @param srcIP
 * @param dstIP
 * @param srcPort
 * @param dstPort
 * @param protocol
 * @param timeOfDay
 * @return pointer to the rule or NULL
 */
inline Rule *
findRule(uint32_t srcIP, uint32_t dstIP, uint16_t srcPort, uint16_t dstPort, uint8_t protocol, uint32_t timeOfDay) {
    for (Rule *rule = cvector_begin(rules); rule != cvector_end(rules); ++rule) {
        if (
            (srcIP & rule->srcMask) == (rule->srcIP & rule->srcMask)
            && (dstIP & rule->dstMask) == (rule->dstIP & rule->dstMask)
            && (!rule->srcPort || srcPort == rule->srcPort)
            && (!rule->dstPort || dstPort == rule->dstPort)
            && (!rule->protocol || protocol == rule->protocol)
            && (
                rule->start > rule->end
                ? (timeOfDay >= rule->start || timeOfDay <= rule->end)
                : (timeOfDay >= rule->start && timeOfDay <= rule->end)
            )
        ) {
            return rule;
        }
    }
    return NULL;
}

/**
 * @brief filter, will be called on NF_INET_PRE_ROUTING and NF_INET_POST_ROUTING
 * @param p never used
 * @param b socket buffer, which will be checked by rules and connections to determine whether the firewall should drop it
 * @param state never used
 * @return NF_ACCEPT or NF_DROP according to rules
 */
uint32_t mainHook(void *p, struct sk_buff *b, const struct nf_hook_state *state) {
    if (!ip_hdr(b)) {
        return NF_ACCEPT;
    }
    uint32_t srcIP = ip_hdr(b)->saddr;
    uint32_t dstIP = ip_hdr(b)->daddr;
    uint8_t protocol = ip_hdr(b)->protocol;
    uint16_t srcPort = 0;
    uint16_t dstPort = 0;
    switch (protocol) {
        case IPPROTO_TCP:
            srcPort = tcp_hdr(b)->source;
            dstPort = tcp_hdr(b)->dest;
            break;
        case IPPROTO_UDP:
            srcPort = udp_hdr(b)->source;
            dstPort = udp_hdr(b)->dest;
            break;
        case IPPROTO_ICMP:
            break;
        default:
            return NF_ACCEPT;
    }
    uint64_t now = ktime_get_real_seconds();
    uint32_t timeOfDay = now % (24 * 60 * 60);
    Connection connection = {
        .srcIP = srcIP,
        .dstIP = dstIP,
        .srcPort = srcPort,
        .dstPort = dstPort,
        .protocol = protocol,
        .expire = now + (protocol == IPPROTO_TCP ? 5 : 1),
    };
    Connection reverseConnection = {
        .srcIP = dstIP,
        .dstIP = srcIP,
        .srcPort = dstPort,
        .dstPort = srcPort,
        .protocol = protocol,
        .expire = now + (protocol == IPPROTO_TCP ? 5 : 1),
    };
    Connection *result = hashmap_get(connections, &connection);
    Connection *reverseResult = hashmap_get(connections, &reverseConnection);
    if (result && now < result->expire) {
        result->expire = connection.expire;
        return NF_ACCEPT;
    }
    if (reverseResult && now < reverseResult->expire) {
        reverseResult->expire = connection.expire;
        return NF_ACCEPT;
    }
    Rule *rule = findRule(srcIP, dstIP, srcPort, dstPort, protocol, timeOfDay);
    if (!rule) {
        hashmap_set(connections, &connection);
        return REJECT_BY_DEFAULT ? NF_DROP : NF_ACCEPT;
    }
    if (rule->log) {
        Log log = {
            .srcIP = srcIP,
            .dstIP = dstIP,
            .srcPort = srcPort,
            .dstPort = dstPort,
            .protocol = protocol,
            .action = rule->action,
            .timestamp = now
        };
        cvector_push_back(logs, log);
    }
    if (rule->action) {
        hashmap_set(connections, &connection);
        return NF_ACCEPT;
    }
    return NF_DROP;
}

/**
 * @brief DNAT, will be called on NF_INET_PRE_ROUTING
 * @param p never used
 * @param b socket buffer, whose destination ip and destination port may be changed
 * @param state never used
 * @return always NF_ACCEPT
 */
uint32_t inboundNATHook(void *p, struct sk_buff *b, const struct nf_hook_state *state) {
    if (!ip_hdr(b) || isLAN(ip_hdr(b)->saddr)) {
        return NF_ACCEPT;
    }
    switch (ip_hdr(b)->protocol) {
        case IPPROTO_TCP:
            if (tcp_hdr(b) && wanNATEntries[tcp_hdr(b)->dest].lanIP) {
                ip_hdr(b)->daddr = wanNATEntries[tcp_hdr(b)->dest].lanIP;
                tcp_hdr(b)->dest = wanNATEntries[tcp_hdr(b)->dest].lanPort;
                updateChecksum(b);
            }
            return NF_ACCEPT;
        case IPPROTO_UDP:
            if (udp_hdr(b) && wanNATEntries[udp_hdr(b)->dest].lanIP) {
                ip_hdr(b)->daddr = wanNATEntries[udp_hdr(b)->dest].lanIP;
                udp_hdr(b)->dest = wanNATEntries[udp_hdr(b)->dest].lanPort;
                updateChecksum(b);
            }
            return NF_ACCEPT;
        default:
            return NF_ACCEPT;
    }
}

/**
 * @brief SNAT, will be called on NF_INET_POST_ROUTING
 * @param p never used
 * @param b socket buffer, whose source ip and source port may be changed
 * @param state never used
 * @return always NF_ACCEPT
 */
uint32_t outboundNATHook(void *p, struct sk_buff *b, const struct nf_hook_state *state) {
    if (!ip_hdr(b) || !isLAN(ip_hdr(b)->saddr)) {
        return NF_ACCEPT;
    }
    switch (ip_hdr(b)->protocol) {
        case IPPROTO_TCP:
            if (tcp_hdr(b)) {
                uint32_t ip = ip_hdr(b)->saddr;
                uint32_t port = tcp_hdr(b)->source;
                ip_hdr(b)->saddr = deviceIP(b->dev);
                NATEntry* res = hashmap_get(lanNATEntries, &(NATEntry){ .lanIP = ip, .lanPort = port });
                tcp_hdr(b)->source = res ? res->wanPort : addNATEntry(ip, port);
                updateChecksum(b);
            }
            return NF_ACCEPT;
        case IPPROTO_UDP:
            if (udp_hdr(b)) {
                uint32_t ip = ip_hdr(b)->saddr;
                uint32_t port = udp_hdr(b)->source;
                ip_hdr(b)->saddr = deviceIP(b->dev);
                NATEntry* res = hashmap_get(lanNATEntries, &(NATEntry){ .lanIP = ip, .lanPort = port });
                udp_hdr(b)->source = res ? res->wanPort : addNATEntry(ip, port);
                updateChecksum(b);
            }
            return NF_ACCEPT;
        default:
            return NF_ACCEPT;
    }
}

/**
 * @brief send data to userspace via netlink
 * @param pid the pid of userspace program
 * @param message message to send
 * @param len length of message
 */
static void netlinkSend(uint32_t pid, const void *message, size_t len) {
    struct sk_buff *b = nlmsg_new(len, GFP_KERNEL);
    if (!b) {
        printk("Failed to allocate sk_buff\n");
    }
    struct nlmsghdr *nlh = nlmsg_put(b, 0, 0, NLMSG_DONE, len, 0);
    NETLINK_CB(b).dst_group = 0;
    memcpy(nlmsg_data(nlh), message, len);
    nlmsg_unicast(netlinkSocket, b, pid);
}

/**
 * @brief will be called when data is received from netlink
 * @param b socket buffer, whose data's first byte is the action, and the following bytes are payload
 */
static void netlinkReceive(struct sk_buff *b) {
    struct nlmsghdr *nlh = nlmsg_hdr(b);
    uint8_t *data = nlmsg_data(nlh);
    switch (*data) {
        case 0: // set rules
            cvector_set_size(rules, 0);
            for (int i = 1; i + sizeof(Rule) < nlh->nlmsg_len; i += sizeof(Rule)) {
                Rule rule;
                memcpy(&rule, data + i, sizeof(Rule));
                cvector_push_back(rules, rule);
            }
            break;
        case 1: // get rules
            netlinkSend(nlh->nlmsg_pid, rules, cvector_size(rules) * sizeof(Rule));
            break;
        case 2: // get connections
            cvector_set_size(activeConnections, 0);
            hashmap_scan(connections, filterConnection, NULL);
            netlinkSend(nlh->nlmsg_pid, activeConnections, cvector_size(activeConnections) * sizeof(Connection));
            break;
        case 3: // get logs
            netlinkSend(nlh->nlmsg_pid, logs, cvector_size(logs) * sizeof(Log));
            break;
        case 4: // clear logs
            cvector_set_size(logs, 0);
            break;
        case 5: // get nat entries
            cvector_set_size(activeNATEntries, 0);
            hashmap_scan(lanNATEntries, filterNATEntry, NULL);
            netlinkSend(nlh->nlmsg_pid, activeNATEntries, cvector_size(activeNATEntries) * sizeof(NATEntry));
            break;
        default:
            break;
    }
}

struct nf_hook_ops inputOps = {
    .hook = mainHook,
    .pf = PF_INET,
    .hooknum = NF_INET_PRE_ROUTING,
    .priority = NF_IP_PRI_FILTER // priority SHOULD be NF_IP_PRI_FILTER, which ensures that `mainHook` executes after `inboundNATHook`
};
struct nf_hook_ops outputOps = {
    .hook = mainHook,
    .pf = PF_INET,
    .hooknum = NF_INET_POST_ROUTING,
    .priority = NF_IP_PRI_FILTER // priority SHOULD be NF_IP_PRI_FILTER, which ensures that `mainHook` executes before `outboundNATHook`
};
struct nf_hook_ops inputNATOps = {
    .hook = inboundNATHook,
    .pf = PF_INET,
    .hooknum = NF_INET_PRE_ROUTING,
    .priority = NF_IP_PRI_NAT_DST // priority SHOULD be NF_IP_PRI_NAT_DST
};
struct nf_hook_ops outputNATOps = {
    .hook = outboundNATHook,
    .pf = PF_INET,
    .hooknum = NF_INET_POST_ROUTING,
    .priority = NF_IP_PRI_NAT_SRC // priority SHOULD be NF_IP_PRI_NAT_SRC
};

/**
 * @brief will be called when the module is initialized, some preparations are done here
 * @return
 */
static int initCallback(void) {
    connections = hashmap_new(sizeof(Connection), 0, 0, 0, hashConnection, compareConnection, NULL);
    if (!connections) {
        printk("Failed to create connections table\n");
	return -1;
    }
    lanNATEntries = hashmap_new(sizeof(NATEntry), 0, 0, 0, hashNATEntry, compareNATEntry, NULL);
    if (!lanNATEntries) {
        printk("Failed to create reverse NAT entries table\n");
	return -1;
    }
    nf_register_net_hook(&init_net, &inputOps);
    nf_register_net_hook(&init_net, &outputOps);
    nf_register_net_hook(&init_net, &inputNATOps);
    nf_register_net_hook(&init_net, &outputNATOps);
    struct netlink_kernel_cfg cfg = {0};
    cfg.input = netlinkReceive;
    netlinkSocket = netlink_kernel_create(&init_net, NETLINK_USER, &cfg);
    if (!netlinkSocket) {
        printk("Failed to create netlink socket\n");
        return -1;
    }
    return 0;
}

/**
 * @brief will be called when the module exits, some cleanups are done here
 * @return
 */
static void exitCallback(void) {
    hashmap_free(connections);
    hashmap_free(lanNATEntries);
    nf_unregister_net_hook(&init_net, &inputOps);
    nf_unregister_net_hook(&init_net, &outputOps);
    nf_unregister_net_hook(&init_net, &inputNATOps);
    nf_unregister_net_hook(&init_net, &outputNATOps);
    netlink_kernel_release(netlinkSocket);
}

module_init(initCallback)

module_exit(exitCallback)

MODULE_LICENSE("GPL");
MODULE_AUTHOR("winderica");
