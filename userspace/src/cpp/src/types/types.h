#ifndef _TYPES_H
#define _TYPES_H

#include <bits/stdc++.h>

struct Rule {
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

    Rule(
        uint32_t src_ip,
        uint32_t src_mask,
        uint32_t dst_ip,
        uint32_t dst_mask,
        uint16_t src_port,
        uint16_t dst_port,
        uint8_t protocol,
        uint8_t action,
        uint8_t log,
        uint32_t start,
        uint32_t end
    ) : src_ip(src_ip), src_mask(src_mask), dst_ip(dst_ip), dst_mask(dst_mask), src_port(src_port), dst_port(dst_port),
        protocol(protocol), action(action), log(log), start(start), end(end) {}

    Rule() = default;
};

struct NATEntry {
    uint32_t lan_ip;
    uint16_t lan_port;
    uint16_t wan_port;
};

struct Connection {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
    uint64_t expire;
} __attribute__((packed));

struct Log {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
    uint8_t action;
    uint64_t timestamp;
};

#endif //_TYPES_H
