#include <linux/netfilter_ipv4.h>
#include <linux/inetdevice.h>
#include <net/tcp.h>
#include <net/udp.h>
#include "lib/hashmap.h"
#include "lib/vector.h"

uint32_t NETLINK_USER = 25;
uint32_t LAN_IP = 0x02A8C0; // 192.168.2.0
uint32_t LAN_MASK = 0xFFFFFF; // 255.255.255.0

typedef struct {
    uint32_t src_ip;
    uint32_t src_mask;
    uint32_t dst_ip;
    uint32_t dst_mask;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
    uint8_t action;
    uint8_t log;
    uint32_t start;
    uint32_t end;
} Rule;
typedef struct {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
    uint64_t expire;
} __attribute__((packed)) Connection;
typedef struct {
    uint32_t lan_ip;
    uint16_t lan_port;
    uint16_t wan_port;
} NATEntry;
typedef struct {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
    uint8_t action;
    uint64_t timestamp;
} Log;

cvector_vector_type(Rule)rules = NULL;
struct hashmap *connections;
cvector_vector_type(Connection)activeConnections = NULL;
cvector_vector_type(Log)logs = NULL;
static NATEntry natEntries[65536];
cvector_vector_type(NATEntry)activeNATEntries = NULL;
uint16_t natPort = 10000;
struct sock *netlinkSocket = NULL;

inline uint8_t isLAN(uint32_t ip) {
    return (ip & LAN_MASK) == LAN_IP;
}

inline uint32_t deviceIP(const struct net_device *dev) {
    if (!dev || !dev->ip_ptr || !dev->ip_ptr->ifa_list) {
        return 0;
    }
    return dev->ip_ptr->ifa_list->ifa_local;
}

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

uint64_t hashConnection(const void *item, uint64_t seed0, uint64_t seed1) {
    return hashmap_sip(item, sizeof(Connection) - sizeof(uint64_t), seed0, seed1);
}

int compareConnection(const void *a, const void *b, void *data) {
    return memcmp(a, b, sizeof(Connection) - sizeof(uint64_t));
}

bool filterConnection(const void *item, void *data) {
    const Connection *connection = item;
    if (ktime_get_real_seconds() < connection->expire) {
        cvector_push_back(activeConnections, *connection);
    }
    return true;
}

uint16_t addNATEntry(uint32_t ip, uint16_t port) {
    uint16_t newPort = natPort++;
    if (natPort == 0) {
        natPort = 10000;
    }
    natEntries[newPort].lan_ip = ip;
    natEntries[newPort].lan_port = port;
    natEntries[newPort].wan_port = newPort;
    return newPort;
}

uint16_t findNATEntry(uint32_t ip, uint16_t port) {
    for (int i = 0; i < 65536; i++) {
        if (natEntries[i].lan_ip == ip && natEntries[i].lan_port == port) {
            return i;
        }
    }
    return 0;
}

void filterNATEntries(void) {
    cvector_set_size(activeNATEntries, 0);
    for (int i = 0; i < 65536; i++) {
        if (natEntries[i].lan_ip) {
            cvector_push_back(activeNATEntries, natEntries[i]);
        }
    }
}

inline Rule *
findRule(uint32_t src_ip, uint32_t dst_ip, uint16_t src_port, uint16_t dst_port, uint8_t protocol, uint32_t timeOfDay) {
    for (Rule *rule = cvector_begin(rules); rule != cvector_end(rules); ++rule) {
        if (
            (src_ip & rule->src_mask) == (rule->src_ip & rule->src_mask)
            && (dst_ip & rule->dst_mask) == (rule->dst_ip & rule->dst_mask)
            && (!rule->src_port || src_port == rule->src_port)
            && (!rule->dst_port || dst_port == rule->dst_port)
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

uint32_t mainHook(void *p, struct sk_buff *b, const struct nf_hook_state *state) {
    if (!ip_hdr(b)) {
        return NF_ACCEPT;
    }
    uint32_t src_ip = ip_hdr(b)->saddr;
    uint32_t dst_ip = ip_hdr(b)->daddr;
    uint8_t protocol = ip_hdr(b)->protocol;
    uint16_t src_port = 0;
    uint16_t dst_port = 0;
    switch (protocol) {
        case IPPROTO_TCP:
            src_port = tcp_hdr(b)->source;
            dst_port = tcp_hdr(b)->dest;
            break;
        case IPPROTO_UDP:
            src_port = udp_hdr(b)->source;
            dst_port = udp_hdr(b)->dest;
            break;
        case IPPROTO_ICMP:
            break;
        default:
            return NF_ACCEPT;
    }
    uint64_t now = ktime_get_real_seconds();
    uint32_t timeOfDay = now % (24 * 60 * 60);
    Connection connection = {
        .src_ip = src_ip,
        .dst_ip = dst_ip,
        .src_port = src_port,
        .dst_port = dst_port,
        .protocol = protocol,
        .expire = now + (protocol == IPPROTO_TCP ? 5 : 1),
    };
    Connection *result = hashmap_get(connections, &connection);
    if (result && now < result->expire) {
        result->expire = connection.expire;
        return NF_ACCEPT;
    }
    Rule *rule = findRule(src_ip, dst_ip, src_port, dst_port, protocol, timeOfDay);
    if (!rule) {
        hashmap_set(connections, &connection);
        return NF_ACCEPT; // TODO: reject by default
    }
    if (rule->log) {
        Log log = {
            .src_ip = src_ip,
            .dst_ip = dst_ip,
            .src_port = src_port,
            .dst_port = dst_port,
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

uint32_t inboundNATHook(void *p, struct sk_buff *b, const struct nf_hook_state *state) {
    if (!ip_hdr(b) || isLAN(ip_hdr(b)->saddr)) {
        return NF_ACCEPT;
    }
    switch (ip_hdr(b)->protocol) {
        case IPPROTO_TCP:
            if (tcp_hdr(b) && natEntries[tcp_hdr(b)->dest].lan_ip) {
                ip_hdr(b)->daddr = natEntries[tcp_hdr(b)->dest].lan_ip;
                tcp_hdr(b)->dest = natEntries[tcp_hdr(b)->dest].lan_port;
                updateChecksum(b);
            }
            return NF_ACCEPT;
        case IPPROTO_UDP:
            if (udp_hdr(b) && natEntries[udp_hdr(b)->dest].lan_ip) {
                ip_hdr(b)->daddr = natEntries[udp_hdr(b)->dest].lan_ip;
                udp_hdr(b)->dest = natEntries[udp_hdr(b)->dest].lan_port;
                updateChecksum(b);
            }
            return NF_ACCEPT;
        default:
            return NF_ACCEPT;
    }
}

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
                tcp_hdr(b)->source = findNATEntry(ip, port) || addNATEntry(ip, port);
                updateChecksum(b);
            }
            return NF_ACCEPT;
        case IPPROTO_UDP:
            if (udp_hdr(b)) {
                uint32_t ip = ip_hdr(b)->saddr;
                uint32_t port = udp_hdr(b)->source;
                ip_hdr(b)->saddr = deviceIP(b->dev);
                udp_hdr(b)->source = findNATEntry(ip, port) || addNATEntry(ip, port);
                updateChecksum(b);
            }
            return NF_ACCEPT;
        default:
            return NF_ACCEPT;
    }
}

static void netlinkSend(uint32_t pid, const void *message, size_t len) {
    struct sk_buff *skb = nlmsg_new(len, GFP_KERNEL);
    if (!skb) {
        printk("Failed to allocate sk_buff\n");
    }
    struct nlmsghdr *nlh = nlmsg_put(skb, 0, 0, NLMSG_DONE, len, 0);
    NETLINK_CB(skb).dst_group = 0;
    memcpy(nlmsg_data(nlh), message, len);
    nlmsg_unicast(netlinkSocket, skb, pid);
}

static void netlinkReceive(struct sk_buff *skb) {
    struct nlmsghdr *nlh = nlmsg_hdr(skb);
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
            filterNATEntries();
            netlinkSend(nlh->nlmsg_pid, activeNATEntries, cvector_size(activeNATEntries) * sizeof(NATEntry));
            break;
        default:
            break;
    }
}

struct nf_hook_ops inputOps = {
    .hook = mainHook,
    .pf = PF_INET,
    .hooknum = NF_INET_LOCAL_IN,
    .priority = NF_IP_PRI_FIRST
};
struct nf_hook_ops outputOps = {
    .hook = mainHook,
    .pf = PF_INET,
    .hooknum = NF_INET_LOCAL_OUT,
    .priority = NF_IP_PRI_FIRST
};
struct nf_hook_ops inputNATOps = {
    .hook = inboundNATHook,
    .pf = PF_INET,
    .hooknum = NF_INET_PRE_ROUTING,
    .priority = NF_IP_PRI_FIRST
};
struct nf_hook_ops outputNATOps = {
    .hook = outboundNATHook,
    .pf = PF_INET,
    .hooknum = NF_INET_POST_ROUTING,
    .priority = NF_IP_PRI_FIRST
};

static int initCallback(void) {
    connections = hashmap_new(sizeof(Connection), 0, 0, 0, hashConnection, compareConnection, NULL);
    if (!connections) {
        printk("Failed to create connections table\n");
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

static void exitCallback(void) {
    hashmap_free(connections);
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
