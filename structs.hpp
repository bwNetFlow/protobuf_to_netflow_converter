#ifndef STRUCTS_HPP
#define STRUCTS_HPP

#define TOPIC "topic"
#define USER "user"
#define PASSWORD "pwd"
#define GROUP_ID "grp_id"
#define BROKERS "brokers"
#define INTERFACE_NAME "iface_name"
#define DESTINATION_IP "dst_ip"
#define DESTINATION_PORT "dst_port"
#define ANONYMIZATION "anonymization"

typedef unsigned __int128 uint128_t;

struct 
user_credentials 
{
    std::string topic;
    std::string user;
    std::string pwd;
    std::string grp_id;
    std::string brokers;
    std::string iface_name;
    std::string dst_ip;
    uint16_t dst_port;
    std::string anonymization;
};

struct
kafka_input
{
    uint64_t pkts; 
    uint64_t bytes;
    std::string IP4SrcAddr;
    std::string IP4DstAddr;
    uint32_t InputSNMP; 
    uint32_t OutputSNMP;
    uint32_t LastSwitched; 
    uint32_t FirstSwitched;
    uint16_t L4SrcPort; 
    uint16_t L4DstPort;
    uint32_t SrcAS; 
    uint32_t DstAS;
    std::string BGPNextHop;
    uint32_t SrcMask; 
    uint32_t DstMask;
    uint16_t Proto; 
    uint16_t TCPFlags; 
    uint16_t IPToS; 
    uint16_t Direction; 
    uint16_t ForwardingStatus;
    uint16_t FlowSamplerID;
    uint32_t IngressVRFID; 
    uint32_t EgressVRFID;
};

struct
kafka_input_v6
{
    uint64_t pkts;
    uint64_t bytes;
    std::string IP6SrcAddr;
    std::string IP6DstAddr;
    uint32_t InputSNMP; 
    uint32_t OutputSNMP;
    uint32_t FirstSwitched; 
    uint32_t LastSwitched;
    uint32_t FlowLabel;
    uint32_t IP6OptionHeaders;
    uint16_t L4SrcPort;
    uint16_t L4DstPort;
    uint32_t SrcAS;
    uint32_t DstAS;
    std::string BGPIP6NextHop;
    uint8_t IP6DstMask;
    uint8_t IP6SrcMask;
    uint8_t Proto;
    uint8_t TCPFlags;
    uint8_t IPToS;
    uint8_t Direction;
    uint8_t ForwardingStatus;
    uint16_t FlowSamplerID; 
    uint32_t IngressVRFID; 
    uint32_t EgressVRFID;
};

#endif
