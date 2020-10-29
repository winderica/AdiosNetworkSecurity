#include <napi.h>
#include <unistd.h>
#include <linux/netlink.h>
#include <arpa/inet.h>
#include "types/types.h"

uint32_t NETLINK_USER = 25;

std::string ipToString(uint32_t ip) {
    char res[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip, res, INET_ADDRSTRLEN);
    return std::string(res);
}

uint32_t parseIP(const std::string &ip) {
    return inet_addr(ip.c_str());
}

uint32_t maskToNumber(uint32_t mask) {
    return std::bitset<32>(mask).count();
}

uint32_t parseMask(uint32_t mask) {
    uint64_t one = 1;
    return (one << mask) - 1;
}

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

std::string actionToString(uint8_t action) {
    return action ? "ACCEPT" : "REJECT";
}

std::string timestampToString(time_t timestamp) {
    char buffer[32];
    strftime(buffer, 32, "%Y-%m-%d %H:%M:%S", localtime(&timestamp));
    return buffer;
}

class NetlinkAPI : public Napi::ObjectWrap<NetlinkAPI> {
private:
    int sd;

    void sendData(void *data, size_t len) const {
        auto nlh = (struct nlmsghdr *) calloc(NLMSG_SPACE(len), 1);
        nlh->nlmsg_len = NLMSG_SPACE(len);
        nlh->nlmsg_pid = getpid();
        memcpy(NLMSG_DATA(nlh), data, len);
        struct iovec iov = {
            .iov_base = (void *) nlh,
            .iov_len = nlh->nlmsg_len,
        };
        struct sockaddr_nl dest_addr = {0};
        dest_addr.nl_family = AF_NETLINK;
        struct msghdr msg = {0};
        msg.msg_name = (void *) &dest_addr;
        msg.msg_namelen = sizeof(dest_addr);
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        sendmsg(sd, &msg, 0);
        free(nlh);
    }

    [[nodiscard]] std::string receiveData() const {
        auto nlh = (struct nlmsghdr *) calloc(NLMSG_SPACE(1024*1024), 1);
        struct iovec iov = {
            .iov_base = (void *) nlh,
            .iov_len = NLMSG_SPACE(1024*1024),
        };
        struct sockaddr_nl source_addr = {0};
        struct msghdr msg = {0};
        msg.msg_name = (void *) &source_addr;
        msg.msg_namelen = sizeof(source_addr);
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

    ~NetlinkAPI() override {
        close(sd);
    }

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

    Napi::Value getRules(const Napi::CallbackInfo &info) {
        sendData((void *) "\x01", 1);
        auto data = receiveData();
        auto env = info.Env();
        auto arr = Napi::Array::New(env, data.length() / sizeof(Rule));
        for (auto i = 0; i < arr.Length(); i++) {
            auto jsRule = Napi::Object::New(env);
            Rule rule{};
            memcpy(&rule, data.c_str() + i * sizeof(Rule), sizeof(Rule));
            jsRule.Set("src_ip", ipToString(rule.src_ip));
            jsRule.Set("src_mask", maskToNumber(rule.src_mask));
            jsRule.Set("dst_ip", ipToString(rule.dst_ip));
            jsRule.Set("dst_mask", maskToNumber(rule.dst_mask));
            jsRule.Set("src_port", ntohs(rule.src_port));
            jsRule.Set("dst_port", ntohs(rule.dst_port));
            jsRule.Set("protocol", protocolToString(rule.protocol));
            jsRule.Set("action", Napi::Boolean::New(env, rule.action));
            jsRule.Set("log", Napi::Boolean::New(env, rule.log));
            jsRule.Set("start", rule.start);
            jsRule.Set("end", rule.end);
            arr.Set(i, jsRule);
        }
        return arr;
    }

    Napi::Value getConnections(const Napi::CallbackInfo &info) {
        sendData((void *) "\x02", 1);
        auto data = receiveData();
        auto env = info.Env();
        auto arr = Napi::Array::New(env, data.length() / sizeof(Connection));
        for (auto i = 0; i < arr.Length(); i++) {
            auto jsConnection = Napi::Object::New(env);
            Connection connection{};
            memcpy(&connection, data.c_str() + i * sizeof(Connection), sizeof(Connection));
            jsConnection.Set("src_ip", ipToString(connection.src_ip));
            jsConnection.Set("dst_ip", ipToString(connection.dst_ip));
            jsConnection.Set("src_port", ntohs(connection.src_port));
            jsConnection.Set("dst_port", ntohs(connection.dst_port));
            jsConnection.Set("protocol", protocolToString(connection.protocol));
            arr.Set(i, jsConnection);
        }
        return arr;
    }

    Napi::Value getLogs(const Napi::CallbackInfo &info) {
        sendData((void *) "\x03", 1);
        auto data = receiveData();
        auto env = info.Env();
        auto arr = Napi::Array::New(env, data.length() / sizeof(Log));
        for (auto i = 0; i < arr.Length(); i++) {
            auto jsLog = Napi::Object::New(env);
            Log log{};
            memcpy(&log, data.c_str() + i * sizeof(Log), sizeof(Log));
            jsLog.Set("src_ip", ipToString(log.src_ip));
            jsLog.Set("dst_ip", ipToString(log.dst_ip));
            jsLog.Set("src_port", ntohs(log.src_port));
            jsLog.Set("dst_port", ntohs(log.dst_port));
            jsLog.Set("protocol", protocolToString(log.protocol));
            jsLog.Set("action", actionToString(log.action));
            jsLog.Set("timestamp", timestampToString(log.timestamp));
            arr.Set(i, jsLog);
        }
        return arr;
    }

    void clearLogs(const Napi::CallbackInfo &) {
        sendData((void *) "\x04", 1);
    }

    Napi::Value getNATEntries(const Napi::CallbackInfo &info) {
        sendData((void *) "\x05", 1);
        auto data = receiveData();
        auto env = info.Env();
        auto arr = Napi::Array::New(env, data.length() / sizeof(NATEntry));
        for (auto i = 0; i < arr.Length(); i++) {
            auto jsNATEntry = Napi::Object::New(env);
            NATEntry natEntry{};
            memcpy(&natEntry, data.c_str() + i * sizeof(NATEntry), sizeof(NATEntry));
            jsNATEntry.Set("lan_ip", ipToString(natEntry.lan_ip));
            jsNATEntry.Set("lan_port", ntohs(natEntry.lan_port));
            jsNATEntry.Set("wan_port", ntohs(natEntry.wan_port));
            arr.Set(i, jsNATEntry);
        }
        return arr;
    }

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

NODE_API_MODULE(hello, Init)
