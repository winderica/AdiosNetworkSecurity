#ifndef _TYPES_H
#define _TYPES_H

#include <bits/stdc++.h>

struct Rule {
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

    Rule(
        uint32_t srcIP,
        uint32_t srcMask,
        uint32_t dstIP,
        uint32_t dstMask,
        uint16_t srcPort,
        uint16_t dstPort,
        uint8_t protocol,
        uint8_t action,
        uint8_t log,
        uint32_t start,
        uint32_t end
    ) : srcIP(srcIP), srcMask(srcMask), dstIP(dstIP), dstMask(dstMask), srcPort(srcPort), dstPort(dstPort),
        protocol(protocol), action(action), log(log), start(start), end(end) {}

    Rule() = default;
};

struct NATEntry {
    uint32_t lanIP;
    uint16_t lanPort;
    uint16_t wanPort;
};

struct Connection {
    uint32_t srcIP;
    uint32_t dstIP;
    uint16_t srcPort;
    uint16_t dstPort;
    uint8_t protocol;
    uint64_t expire;
} __attribute__((packed));

struct Log {
    uint32_t srcIP;
    uint32_t dstIP;
    uint16_t srcPort;
    uint16_t dstPort;
    uint8_t protocol;
    uint8_t action;
    uint64_t timestamp;
};

#endif //_TYPES_H
