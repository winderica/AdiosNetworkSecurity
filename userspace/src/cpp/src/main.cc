#include <napi.h>
#include <unistd.h>
#include <linux/netlink.h>
#include <arpa/inet.h>
#include "types/types.h"

uint32_t NETLINK_USER = 31;

/**
 * @brief convert ip to string
 * @param ip
 * @return
 */
std::string ipToString(uint32_t ip) {
    char res[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip, res, INET_ADDRSTRLEN);
    return std::string(res);
}

/**
 * @brief convert string to IP
 * @param ip
 * @return
 */
uint32_t parseIP(const std::string &ip) {
    return inet_addr(ip.c_str());
}

/**
 * @brief convert CIDR mask to IP mask
 * @param mask
 * @return
 */
uint32_t maskToNumber(uint32_t mask) {
    return std::bitset<32>(mask).count();
}

/**
 * @brief convert IP mask to CIDR mask
 * @param mask
 * @return
 */
uint32_t parseMask(uint32_t mask) {
    uint64_t one = 1;
    return (one << mask) - 1;
}

/**
 * @brief convert protocol enum to string
 * @param protocol
 * @return
 */
std::string protocolToString(uint8_t protocol) {
    switch (protocol) {
        case IPPROTO_TCP:
            return "TCP";
        case IPPROTO_UDP:
            return "UDP";
        case IPPROTO_ICMP:
            return "ICMP";
        case 0:
            return "ANY";
        default:
            return "UNKNOWN";
    }
}

/**
 * @brief convert string to protocol enum
 * @param protocol
 * @return
 */
uint8_t parseProtocol(const std::string &protocol) {
    auto map = std::unordered_map<std::string, uint8_t>(
        {
            {"TCP",  IPPROTO_TCP},
            {"UDP",  IPPROTO_UDP},
            {"ICMP", IPPROTO_ICMP},
        }
    );
    if (map.count(protocol)) {
        return map[protocol];
    }
    return 0;
}

/**
 * @brief convert action to string
 * @param action
 * @return
 */
std::string actionToString(uint8_t action) {
    return action ? "ACCEPT" : "REJECT";
}

/**
 * @brief format timestamp
 * @param timestamp
 * @return
 */
std::string timestampToString(time_t timestamp) {
    char buffer[32];
    strftime(buffer, 32, "%Y-%m-%d %H:%M:%S", localtime(&timestamp));
    return buffer;
}

/**
 * @brief `NetlinkAPI` is provided to JS by node addon
 */
class NetlinkAPI : public Napi::ObjectWrap<NetlinkAPI> {
private:
    int sd;

    /**
     * @brief send data to kernel module via netlink
     * @param data
     * @param len
     */
    void sendData(void *data, size_t len) const {
        auto nlh = (struct nlmsghdr *) calloc(NLMSG_SPACE(len), 1);
        nlh->nlmsg_len = NLMSG_SPACE(len);
        nlh->nlmsg_pid = getpid();
        memcpy(NLMSG_DATA(nlh), data, len);
        struct iovec iov = {
            .iov_base = (void *) nlh,
            .iov_len = nlh->nlmsg_len,
        };
        struct sockaddr_nl addr = {0};
        addr.nl_family = AF_NETLINK;
        struct msghdr msg = {0};
        msg.msg_name = (void *) &addr;
        msg.msg_namelen = sizeof(addr);
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        sendmsg(sd, &msg, 0);
        free(nlh);
    }

    /**
     * @brief receive data from kernel module via netlink
     * @return
     */
    [[nodiscard]] std::string receiveData() const {
        auto nlh = (struct nlmsghdr *) calloc(NLMSG_SPACE(1024 * 1024), 1);
        struct iovec iov = {
            .iov_base = (void *) nlh,
            .iov_len = NLMSG_SPACE(1024 * 1024),
        };
        struct sockaddr_nl addr = {0};
        struct msghdr msg = {0};
        msg.msg_name = (void *) &addr;
        msg.msg_namelen = sizeof(addr);
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        if (recvmsg(sd, &msg, 0) == -1) {
            return "";
        }
        auto len = nlh->nlmsg_len - NLMSG_SPACE(0);
        auto data = std::string((char *) NLMSG_DATA(nlh), len);
        free(nlh);
        return data;
    }

public:
    /**
     * @brief connect to kernel module in constructor, which may fail, but it will try to reconnect when refreshing frontend
     * @param info
     */
    explicit NetlinkAPI(const Napi::CallbackInfo &info) : ObjectWrap(info) {
        sd = socket(AF_NETLINK, SOCK_RAW, NETLINK_USER);
        if (sd == -1) {
            throw std::runtime_error("Failed to create socket");
        }
        struct sockaddr_nl addr = {0};
        addr.nl_family = AF_NETLINK;
        addr.nl_pid = getpid();
        if (bind(sd, (struct sockaddr *) &addr, sizeof(struct sockaddr_nl)) < 0) {
            close(sd);
            throw std::runtime_error("Failed to bind");
        }
    }

    /**
     * @brief close socket in destructor
     */
    ~NetlinkAPI() override {
        close(sd);
    }

    /**
     * @brief send rules from JS to kernel
     * @param info array of `Rule`s
     */
    void sendRules(const Napi::CallbackInfo &info) {
        auto rules = info[0].As<Napi::Array>();
        std::vector<Rule> cppRules;
        for (auto i = 0; i < rules.Length(); i++) {
            auto rule = rules.Get(i).As<Napi::Object>();
            cppRules.emplace_back(
                parseIP(rule.Get("src_ip").As<Napi::String>().Utf8Value()),
                parseMask(rule.Get("src_mask").As<Napi::Number>().Int32Value()),
                parseIP(rule.Get("dst_ip").As<Napi::String>().Utf8Value()),
                parseMask(rule.Get("dst_mask").As<Napi::Number>().Int32Value()),
                htons(rule.Get("src_port").As<Napi::Number>().Int32Value()),
                htons(rule.Get("dst_port").As<Napi::Number>().Int32Value()),
                parseProtocol(rule.Get("protocol").As<Napi::String>().Utf8Value()),
                rule.Get("action").As<Napi::Boolean>().Value(),
                rule.Get("log").As<Napi::Boolean>().Value(),
                rule.Get("start").As<Napi::Number>().Int32Value(),
                rule.Get("end").As<Napi::Number>().Int32Value()
            );
        }
        auto data = (uint8_t *) malloc(1 + cppRules.size() * sizeof(Rule));
        data[0] = 0;
        memcpy(data + 1, cppRules.data(), cppRules.size() * sizeof(Rule));
        sendData(data, 1 + cppRules.size() * sizeof(Rule));
        free(data);
    }

    /**
     * @brief get rules from kernel and pass them to JS
     * @param info nothing should be provided
     * @return array of `Rule`s
     */
    Napi::Value getRules(const Napi::CallbackInfo &info) {
        sendData((void *) "\x01", 1);
        auto data = receiveData();
        auto env = info.Env();
        auto arr = Napi::Array::New(env, data.length() / sizeof(Rule));
        for (auto i = 0; i < arr.Length(); i++) {
            auto jsRule = Napi::Object::New(env);
            Rule rule{};
            memcpy(&rule, data.c_str() + i * sizeof(Rule), sizeof(Rule));
            jsRule.Set("src_ip", ipToString(rule.srcIP));
            jsRule.Set("src_mask", maskToNumber(rule.srcMask));
            jsRule.Set("dst_ip", ipToString(rule.dstIP));
            jsRule.Set("dst_mask", maskToNumber(rule.dstMask));
            jsRule.Set("src_port", ntohs(rule.srcPort));
            jsRule.Set("dst_port", ntohs(rule.dstPort));
            jsRule.Set("protocol", protocolToString(rule.protocol));
            jsRule.Set("action", Napi::Boolean::New(env, rule.action));
            jsRule.Set("log", Napi::Boolean::New(env, rule.log));
            jsRule.Set("start", rule.start);
            jsRule.Set("end", rule.end);
            arr.Set(i, jsRule);
        }
        return arr;
    }

    /**
     * @brief get active connections from kernel and pass them to JS
     * @param info nothing should be provided
     * @return array of `Connection`s
     */
    Napi::Value getConnections(const Napi::CallbackInfo &info) {
        sendData((void *) "\x02", 1);
        auto data = receiveData();
        auto env = info.Env();
        auto arr = Napi::Array::New(env, data.length() / sizeof(Connection));
        for (auto i = 0; i < arr.Length(); i++) {
            auto jsConnection = Napi::Object::New(env);
            Connection connection{};
            memcpy(&connection, data.c_str() + i * sizeof(Connection), sizeof(Connection));
            jsConnection.Set("src_ip", ipToString(connection.srcIP));
            jsConnection.Set("dst_ip", ipToString(connection.dstIP));
            jsConnection.Set("src_port", ntohs(connection.srcPort));
            jsConnection.Set("dst_port", ntohs(connection.dstPort));
            jsConnection.Set("protocol", protocolToString(connection.protocol));
            arr.Set(i, jsConnection);
        }
        return arr;
    }

    /**
     * @brief get logs from kernel and pass them to JS
     * @param info nothing should be provided
     * @return array of `Log`s
     */
    Napi::Value getLogs(const Napi::CallbackInfo &info) {
        sendData((void *) "\x03", 1);
        auto data = receiveData();
        auto env = info.Env();
        auto arr = Napi::Array::New(env, data.length() / sizeof(Log));
        for (auto i = 0; i < arr.Length(); i++) {
            auto jsLog = Napi::Object::New(env);
            Log log{};
            memcpy(&log, data.c_str() + i * sizeof(Log), sizeof(Log));
            jsLog.Set("src_ip", ipToString(log.srcIP));
            jsLog.Set("dst_ip", ipToString(log.dstIP));
            jsLog.Set("src_port", ntohs(log.srcPort));
            jsLog.Set("dst_port", ntohs(log.dstPort));
            jsLog.Set("protocol", protocolToString(log.protocol));
            jsLog.Set("action", actionToString(log.action));
            jsLog.Set("timestamp", timestampToString(log.timestamp));
            arr.Set(i, jsLog);
        }
        return arr;
    }

    /**
     * @brief clear logs in kernel
     */
    void clearLogs(const Napi::CallbackInfo &) {
        sendData((void *) "\x04", 1);
    }

    /**
     * @brief get NAT entries from kernel and pass them to JS
     * @param info nothing should be provided
     * @return array of `NATEntry`s
     */
    Napi::Value getNATEntries(const Napi::CallbackInfo &info) {
        sendData((void *) "\x05", 1);
        auto data = receiveData();
        auto env = info.Env();
        auto arr = Napi::Array::New(env, data.length() / sizeof(NATEntry));
        for (auto i = 0; i < arr.Length(); i++) {
            auto jsNATEntry = Napi::Object::New(env);
            NATEntry natEntry{};
            memcpy(&natEntry, data.c_str() + i * sizeof(NATEntry), sizeof(NATEntry));
            jsNATEntry.Set("lan_ip", ipToString(natEntry.lanIP));
            jsNATEntry.Set("lan_port", ntohs(natEntry.lanPort));
            jsNATEntry.Set("wan_port", ntohs(natEntry.wanPort));
            arr.Set(i, jsNATEntry);
        }
        return arr;
    }

    /**
     * @brief tell JS what methods are exposed
     * @param env
     * @return
     */
    static Napi::Function getClass(Napi::Env env) {
        return DefineClass(env, "NetlinkAPI", {
            InstanceMethod("sendRules", &NetlinkAPI::sendRules),
            InstanceMethod("getRules", &NetlinkAPI::getRules),
            InstanceMethod("getConnections", &NetlinkAPI::getConnections),
            InstanceMethod("getLogs", &NetlinkAPI::getLogs),
            InstanceMethod("getNATEntries", &NetlinkAPI::getNATEntries),
            InstanceMethod("clearLogs", &NetlinkAPI::clearLogs),
        });
    }
};

static Napi::Object Init(Napi::Env env, Napi::Object exports) {
    exports.Set(Napi::String::New(env, "NetlinkAPI"), NetlinkAPI::getClass(env));
    return exports;
}

NODE_API_MODULE(firewall, Init)
