/* ---

Copyright (C) 2019 Leonard Bradatsch (leo.bradatsch@gmail.com)

--- */

/* ---
    TODO:   - Avoiding memcpy system calls in pack_packet(...) function
            by including l3 and l4 header structs in NetFlowBuilder class.
--- */

#include <sys/ioctl.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <cstddef>
#include <limits.h>
#include <fstream>
#include <ctime>
#include <iostream>
#include <string>
#include <cstdlib>
#include <csignal>
#include <cstring>
#include <openssl/x509.h>
#include <stdlib.h>
#include <iomanip>
#include <unordered_map>
#include <arpa/inet.h>
#include <stdio.h>
#include <netdb.h>
#include <netinet/in.h>
//#include <vector>
#include <arpa/nameser.h>
#include <resolv.h>
#include <chrono>
#include <signal.h>
#include <sys/wait.h>
#include <thread>

#include <sys/time.h>

#include <getopt.h>
#include <unistd.h>

// KAFKA PATH IS INCLUDED BY THE GCC

#include "flow-messages-enriched.pb.h"
#include "consumer.hpp"
#include "structs.hpp"
#include "anonymization.hpp"
#include "netflow_builder.hpp"
#include "input_parser.hpp"

#define IP4_HDRLEN 20
#define UDP_HDRLEN 8
#define SAMPLERID 1
#define IPV4 0x0800
#define IPV6 0x86dd

const uint16_t header_count = NetFlowBuilder{}.get_header_count();
const uint16_t dataHeader_length = NetFlowBuilder{}.get_dataHeader_length();
const uint16_t template_length = NetFlowBuilder{}.get_template_length();
const uint16_t template_fieldCount = NetFlowBuilder{}.get_template_fieldCount();

const uint16_t header_count_v6 = NetFlowBuilderv6{}.get_header_count();
const uint16_t dataHeader_length_v6 = NetFlowBuilderv6{}.get_dataHeader_length();
const uint16_t template_length_v6 = NetFlowBuilderv6{}.get_template_length();
const uint16_t template_fieldCount_v6 = NetFlowBuilderv6{}.get_template_fieldCount();

volatile sig_atomic_t signal_caught = 0;

/* --- Prints how to use the exporter --- */
void
usage(char const* const _cmdname)
{
    std::string usemsg_prefix{"Usage: "};
    std::string cmdname{_cmdname};
    //std::string usemsg_postfix{" <topic> <user> <pwd> <grp_id> <brokers> <iface> <dst_ip> <dst_port> <anonymization>"};
    std::string usemsg_postfix{" <path/to/config_file> "};
    std::cerr << usemsg_prefix << cmdname << usemsg_postfix << std::endl;
}

/* --- TODO: Input verification --- */
int
setup_user_credentials(user_credentials& input, char** argv)
{
    argv++;
    std::string filename{*argv};

    if(read_configFile(filename, input) < 0) return -1;

    return 0;
}

/* --- Computing the internet checksum (RFC 1071).  ---*/
/* --- Function Copyright (C) 2011-2015  P.D. Buchan (pdbuchan@yahoo.com) --- */
uint16_t
ip4_checksum(uint16_t* addr, size_t len)
{
    size_t count = len;
    uint32_t sum = 0;
    uint16_t answer = 0;

    while(count > 1) {
        sum += *(addr++);
        count -= 2;
    }

    if(count > 0) {
        sum += *(uint8_t*) addr;
    }

    while(sum >> 16) {
        sum += (sum & 0xffff) + (sum >> 16);
    }

    answer = ~sum;

    return answer;
}

/* --- Computing the UDP checksum (RFC 768) --- */
/* --- Currently returns always zero as the peer routers. --- */
uint16_t
udp_checksum ()
{
    return 0;
}

/* ---  Return an IP4 struct with default values for UDP; --- */
int 
prepare_ip4_hdr(struct ip& tmp_ip, size_t l7_payload_length, std::string src_ip, std::string dst_ip)
{
    tmp_ip.ip_hl = 5;
    tmp_ip.ip_v = 4;
    tmp_ip.ip_tos = 0;
    tmp_ip.ip_len = IP4_HDRLEN + UDP_HDRLEN + l7_payload_length;
    tmp_ip.ip_id = 0;
    tmp_ip.ip_off = 0;
    tmp_ip.ip_ttl = 255;
    tmp_ip.ip_p = IPPROTO_UDP;
    tmp_ip.ip_sum = 0;
    if(inet_pton(AF_INET, src_ip.c_str(), &(tmp_ip.ip_src)) <= 0) return -1;
    if(inet_pton(AF_INET, dst_ip.c_str(), &(tmp_ip.ip_dst)) <= 0) return -1;
    tmp_ip.ip_sum = ip4_checksum((uint16_t*) &tmp_ip, IP4_HDRLEN);

    return 0;
}

/* --- Return an UDP struct with default values --- */
int
prepare_udp_hdr(struct udphdr& tmp_udp, uint16_t src_port, uint16_t dst_port, size_t l7_payload_length)
{
    tmp_udp.source = htons(src_port);
    tmp_udp.dest = htons(dst_port);
    tmp_udp.len = htons(UDP_HDRLEN + l7_payload_length);
    tmp_udp.check = udp_checksum();

    return 0;
}

/* --- Returns pointer to final packet incl. l7, l4 and l3 --- */
void*
pack_packet(struct ip& tmp_ip, struct udphdr& tmp_udp, void const* payload, size_t payload_size)
{
    size_t packet_size = IP4_HDRLEN + UDP_HDRLEN + payload_size;
    void* ptr = malloc(packet_size * sizeof(uint8_t));
    if(!ptr) return NULL;
    memcpy(ptr, (void*) &tmp_ip, IP4_HDRLEN);
    memcpy(((char*) ptr + IP4_HDRLEN), (void*) &tmp_udp, UDP_HDRLEN);
    memcpy(((char*) ptr + IP4_HDRLEN + UDP_HDRLEN), payload, payload_size);
    return ptr;
}

int
lookup_ifindex(struct ifreq& ifr, std::string interface)
{
    int socketfd;

    if ((socketfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
        std::cerr << "Could not look up iface index (1)." << std::endl;
        return -1;
    }

    memset(&ifr, 0, sizeof ifr);
    memcpy((void*) &ifr, (void*) interface.c_str(), interface.size());
    if (ioctl (socketfd, SIOCGIFINDEX, &ifr) < 0) {
        std::cerr << "Could not look up iface index (1)." << std::endl;
        return -1;
    }

    close(socketfd);
    return 0;
}

int
prepare_raw_socket(std::string interface)
{
    int _true = 1;
    int socketfd;
    struct ifreq ifinfo;

    if(lookup_ifindex(ifinfo, interface) < 0) return -1;

    if ((socketfd = socket (AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
        std::cerr << "Could not set up raw socket (1)." << std::endl;
        return -1;
    }

    if (setsockopt (socketfd, IPPROTO_IP, IP_HDRINCL, &_true, sizeof (_true)) < 0) {
         std::cerr << "Could not set up raw socket (2)." << std::endl;
        return -1;
    }

    if (setsockopt (socketfd, SOL_SOCKET, SO_BINDTODEVICE, &ifinfo, sizeof (ifinfo)) < 0) {
         std::cerr << "Could not set up raw socket (3)." << std::endl;
        return -1;
    }

    return socketfd;
}

uint32_t
add_timediff()
{
    time_t rawtime;
    struct tm* timeinfo;
    char buffer[10];
    time(&rawtime);
    timeinfo = localtime(&rawtime);
    strftime(buffer, sizeof(buffer), "%Z", timeinfo);
    
    if(strcmp(buffer, "CEST") >= 0) return 7200000;
    else if(strcmp(buffer, "CES") >= 0) return 3600000;
    else return 0;
}

uint32_t
calc_sysUptime()
{
    std::chrono::milliseconds uptime(0u);
    double uptime_seconds;
    if(std::ifstream("/proc/uptime", std::ios::in) >> uptime_seconds) {
        uptime = std::chrono::milliseconds(static_cast<unsigned long long>(uptime_seconds)*1000ULL);
    }

    return uptime.count();
}



const std::string 
get_ca_location()
{
    const char* dir;
    dir = getenv(X509_get_default_cert_dir_env());
    if(!dir) dir = X509_get_default_cert_dir();
    return std::string{dir};
}

void
signalhandler(int sig)
{
    signal_caught = sig;
}

int
read_kafka_input(flowmessageenriched::FlowMessage& flowmsg, kafka_input& kafka_values)
{
    kafka_values.bytes = flowmsg.bytes(); // Value is multiplied by 32 coz the router sampling
    kafka_values.pkts = flowmsg.packets(); // Value is multiplied by 32 coz the router sampling
    kafka_values.IP4SrcAddr = flowmsg.srcaddr();
    kafka_values.IP4DstAddr = flowmsg.dstaddr();
    kafka_values.InputSNMP = flowmsg.srcif();
    kafka_values.OutputSNMP = flowmsg.dstif();
    //kafka_values.LastSwitched = flowmsg.timeflowend() + calc_sysUptime() - flowmsg.timereceived() * 1000;
    kafka_values.LastSwitched = (flowmsg.timeflowend() * 1000 - std::time(0) * 1000 + calc_sysUptime()) + add_timediff();
    //kafka_values.FirstSwitched = flowmsg.timeflowstart() + calc_sysUptime() - flowmsg.timereceived() * 1000;
    kafka_values.FirstSwitched = (flowmsg.timeflowstart() * 1000 - std::time(0) * 1000 + calc_sysUptime()) + add_timediff();
    kafka_values.L4SrcPort = flowmsg.srcport();
    kafka_values.L4DstPort = flowmsg.dstport();
    kafka_values.SrcAS = flowmsg.srcas();
    kafka_values.DstAS = flowmsg.dstas();
    kafka_values.BGPNextHop = flowmsg.nexthop();
    kafka_values.SrcMask = flowmsg.srcnet();
    kafka_values.DstMask = flowmsg.dstnet();
    kafka_values.Proto = flowmsg.proto();
    kafka_values.TCPFlags = flowmsg.tcpflags();
    kafka_values.IPToS = flowmsg.iptos();
    kafka_values.Direction = flowmsg.flowdirection();
    kafka_values.ForwardingStatus = flowmsg.forwardingstatus();
    kafka_values.FlowSamplerID = SAMPLERID;
    kafka_values.IngressVRFID = flowmsg.ingressvrfid(); 
    kafka_values.EgressVRFID = flowmsg.egressvrfid(); 

    return 1;
}

int
read_kafka_input_v6(flowmessageenriched::FlowMessage& flowmsg, kafka_input_v6& kafka_values)
{
    kafka_values.bytes = flowmsg.bytes(); // Value is multiplied by 32 coz the router sampling
    kafka_values.pkts = flowmsg.packets(); // Value is multiplied by 32 coz the router sampling
    kafka_values.IP6SrcAddr = flowmsg.srcaddr();
    kafka_values.IP6DstAddr = flowmsg.dstaddr();
    kafka_values.InputSNMP = flowmsg.srcif();
    kafka_values.OutputSNMP = flowmsg.dstif();
    //kafka_values.FirstSwitched = flowmsg.timeflowstart() + calc_sysUptime() - flowmsg.timereceived() * 1000;
    kafka_values.FirstSwitched = (flowmsg.timeflowstart() * 1000 - std::time(0) * 1000 + calc_sysUptime()) + add_timediff();
    //kafka_values.LastSwitched = flowmsg.timeflowend() + calc_sysUptime() - flowmsg.timereceived() * 1000;
    kafka_values.LastSwitched = (flowmsg.timeflowend() * 1000 - std::time(0) * 1000 + calc_sysUptime()) + add_timediff();
    kafka_values.FlowLabel = flowmsg.ipv6flowlabel();
    kafka_values.IP6OptionHeaders = 0x00000000; // Not yet supported by goflow SHAME
    kafka_values.L4SrcPort = flowmsg.srcport();
    kafka_values.L4DstPort = flowmsg.dstport();
    kafka_values.SrcAS = flowmsg.srcas();
    kafka_values.DstAS = flowmsg.dstas();
    kafka_values.BGPIP6NextHop = flowmsg.nexthop();
    kafka_values.IP6DstMask = flowmsg.srcnet();
    kafka_values.IP6SrcMask = flowmsg.dstnet();
    kafka_values.Proto = flowmsg.proto();
    kafka_values.TCPFlags = flowmsg.tcpflags();
    kafka_values.IPToS = flowmsg.iptos();
    kafka_values.Direction = flowmsg.flowdirection();
    kafka_values.ForwardingStatus = flowmsg.forwardingstatus();
    kafka_values.FlowSamplerID = SAMPLERID;
    kafka_values.IngressVRFID = flowmsg.ingressvrfid(); 
    kafka_values.EgressVRFID = flowmsg.egressvrfid();

    return 1;
}

/* ---
    TODO:   Line 295: removing the created object if init_memory() fails;
--- */
int
ip4_handler(user_credentials const& usr_cds, std::unordered_map<std::string, NetFlowBuilder>& input, 
    flowmessageenriched::FlowMessage& flowmsg) 
{
    // NetFlow Variables
    kafka_input kafka_values{};

    char routerAddr_buf[INET_ADDRSTRLEN];
    std::string raw_routerAddr, printable_routerAddr;

    raw_routerAddr = flowmsg.sampleraddress();
    inet_ntop(AF_INET, raw_routerAddr.c_str(), routerAddr_buf, INET_ADDRSTRLEN);
    printable_routerAddr = routerAddr_buf;

    if(input.find(printable_routerAddr) == input.end()) {
        input[printable_routerAddr] = NetFlowBuilder{};
        if(input[printable_routerAddr].init_memory() == -1) {
            std::cerr << "Could not allocate memory! Aborting..." << std::endl;
            return -1;
        }

        // Header Length: 20 Byte
        input[printable_routerAddr].add_header(0x0009, header_count, calc_sysUptime(), std::time(0), 1, raw_routerAddr);
        // Template Length: 100 Byte
        input[printable_routerAddr].add_template(0x0000, template_length, 0x0104, template_fieldCount);
        // Data Header Length: 4 Byte
        input[printable_routerAddr].add_dataHeader(0x0104, dataHeader_length);

        read_kafka_input(flowmsg, kafka_values);
        
        if(usr_cds.anonymization == "yes") {
            make_flow_anonymous_v4(kafka_values);
        }

        input[printable_routerAddr].add_data(kafka_values.pkts, kafka_values.bytes, kafka_values.IP4SrcAddr, 
            kafka_values.IP4DstAddr, kafka_values.InputSNMP, kafka_values.OutputSNMP, kafka_values.LastSwitched, 
            kafka_values.FirstSwitched, kafka_values.L4SrcPort, kafka_values.L4DstPort, 
            kafka_values.SrcAS, kafka_values.DstAS, kafka_values.BGPNextHop, kafka_values.SrcMask, 
            kafka_values.DstMask, kafka_values.Proto, kafka_values.TCPFlags, 
            kafka_values.IPToS, kafka_values.Direction, kafka_values.ForwardingStatus, kafka_values.FlowSamplerID, 
            kafka_values.IngressVRFID, kafka_values.EgressVRFID);
    } else {
        read_kafka_input(flowmsg, kafka_values);

        if(usr_cds.anonymization == "yes") {
            make_flow_anonymous_v4(kafka_values);
        }
        /* ---  While is false as long as the capacity is full; 
                as soon as new space is free the flow is added and while loop is leavd  --- */
        while(!input[printable_routerAddr].add_data(kafka_values.pkts, kafka_values.bytes, kafka_values.IP4SrcAddr, 
            kafka_values.IP4DstAddr, kafka_values.InputSNMP, kafka_values.OutputSNMP, kafka_values.LastSwitched, 
            kafka_values.FirstSwitched, kafka_values.L4SrcPort, kafka_values.L4DstPort, kafka_values.SrcAS, 
            kafka_values.DstAS, kafka_values.BGPNextHop, kafka_values.SrcMask, kafka_values.DstMask, kafka_values.Proto, 
            kafka_values.TCPFlags, kafka_values.IPToS, kafka_values.Direction,
            kafka_values.ForwardingStatus, kafka_values.FlowSamplerID, kafka_values.IngressVRFID, kafka_values.EgressVRFID));
    }

    return 1;
}

/* ---
    TODO:   Line 358: removing the created object if init_memory() fails;
--- */
int
ip6_handler(user_credentials const& usr_cds, std::unordered_map<std::string, NetFlowBuilderv6>& inputv6, 
    flowmessageenriched::FlowMessage& flowmsg)
{
    // NetFlow Variables v6
    kafka_input_v6 kafka_values{};

    char routerAddr_buf[INET_ADDRSTRLEN];
    std::string raw_routerAddr, printable_routerAddr;

    raw_routerAddr = flowmsg.sampleraddress();
    inet_ntop(AF_INET, raw_routerAddr.c_str(), routerAddr_buf, INET_ADDRSTRLEN);
    printable_routerAddr = routerAddr_buf;

    if(inputv6.find(printable_routerAddr) == inputv6.end()) {
        inputv6[printable_routerAddr] = NetFlowBuilderv6{};
        if(inputv6[printable_routerAddr].init_memory() == -1) {
            std::cerr << "Could not allocate memory! Aborting..." << std::endl;
            return -1;
        }

        // Header Length: 20 Byte NEED UPDATE FOR v6
        inputv6[printable_routerAddr].add_header(0x0009, header_count_v6, calc_sysUptime(), std::time(0), 1, raw_routerAddr);
        // Template Length: 100 Byte NEED UPDATE FOR v6
        inputv6[printable_routerAddr].add_template(0x0000, template_length_v6, 0x010a, template_fieldCount_v6);
        // Data Header Length: 4 Byte NEED UPDATE FOR v6
        inputv6[printable_routerAddr].add_dataHeader(0x010a, dataHeader_length_v6);

        read_kafka_input_v6(flowmsg, kafka_values);

        inputv6[printable_routerAddr].add_data(kafka_values.pkts, kafka_values.bytes, kafka_values.IP6SrcAddr, 
            kafka_values.IP6DstAddr, kafka_values.InputSNMP, kafka_values.OutputSNMP, kafka_values.FirstSwitched,
            kafka_values.LastSwitched, kafka_values.FlowLabel, kafka_values.IP6OptionHeaders,
            kafka_values.L4SrcPort, kafka_values.L4DstPort, kafka_values.SrcAS, kafka_values.DstAS,
            kafka_values.BGPIP6NextHop, kafka_values.IP6DstMask, kafka_values.IP6SrcMask, 
            kafka_values.Proto, kafka_values.TCPFlags, kafka_values.IPToS, kafka_values.Direction,
            kafka_values.ForwardingStatus, kafka_values.FlowSamplerID, kafka_values.IngressVRFID, kafka_values.EgressVRFID);

    } else {
        read_kafka_input_v6(flowmsg, kafka_values);

        while(!inputv6[printable_routerAddr].add_data(kafka_values.pkts, kafka_values.bytes, kafka_values.IP6SrcAddr, 
            kafka_values.IP6DstAddr, kafka_values.InputSNMP, kafka_values.OutputSNMP, kafka_values.FirstSwitched,
            kafka_values.LastSwitched, kafka_values.FlowLabel, kafka_values.IP6OptionHeaders,
            kafka_values.L4SrcPort, kafka_values.L4DstPort, kafka_values.SrcAS, kafka_values.DstAS,
            kafka_values.BGPIP6NextHop, kafka_values.IP6DstMask, kafka_values.IP6SrcMask, 
            kafka_values.Proto, kafka_values.TCPFlags, kafka_values.IPToS, kafka_values.Direction,
            kafka_values.ForwardingStatus, kafka_values.FlowSamplerID, kafka_values.IngressVRFID, kafka_values.EgressVRFID));
    }

    return 1;
}

int
flow_consumer(user_credentials const& usr_cds, std::unordered_map<std::string, NetFlowBuilder>& input,
    std::unordered_map<std::string, NetFlowBuilderv6>& inputv6)
{
    std::cout << ">> Protobuf Consumer Thread here..." << std::endl;

    std::vector<std::string> topics{usr_cds.topic};
    Consumer subscriber{usr_cds.user, usr_cds.pwd, usr_cds.grp_id, "sasl_ssl", "PLAIN", get_ca_location(), usr_cds.brokers};
    if(subscriber.init_consumer_default() < 0) {
        std::cerr << "Could not set default consumer values. Exiting..." << std::endl; return -1;
    }
    if(subscriber.add_topics(topics) < 0) {
        std::cerr << "Could not set tpics. Exiting..." << std::endl; return -1;
    }
    if(subscriber.subscribe() < 0) {
        std::cerr << "Could not subcribe on topic. Exiting..." << std::endl; return -1;
    }

    flowmessageenriched::FlowMessage flowmsg{}; // Contains the actual flow
    uint32_t type; // Describes L3 type of the flow

    /* --- EXPERIMENTAL --- */
    while(!signal_caught) {
        std::shared_ptr<RdKafka::Message> msg = subscriber.consume(1000);
        if(msg->len()) {

            std::string tmp_string{};
            tmp_string.resize(msg->len());
            memcpy((void*) &tmp_string[0], msg->payload(), msg->len());
            flowmsg.ParseFromString(tmp_string);

            /* --- Sorts all incoming flows on the basis of L3 TYPE --- */
            type = flowmsg.etype();
            if(type == IPV6) {
                ip6_handler(usr_cds, inputv6, flowmsg);
            } else if(type == IPV4) {
                ip4_handler(usr_cds, input, flowmsg);
                ;
            } else {
                ;
            }
        }
    }
    /* --- END EXPERIMENTAL --- */
    
    subscriber.close();
    return 0;
}

int
flow_writer(user_credentials const& usr_cds, std::unordered_map<std::string, NetFlowBuilder>& input)
{
    std::cout << ">> IP4 Writer Thread here..." << std::endl;
   
    /* --- Socket and Sendto preparement block --- */
    int sd = prepare_raw_socket(usr_cds.iface_name);
    if(sd < 0) exit(EXIT_FAILURE);
    struct sockaddr_in sin;
    memset(&sin, 0, sizeof(struct sockaddr_in));
    sin.sin_family = AF_INET; 
    
    while(!signal_caught) {
        for(auto& it : input) {
            if(it.second.is_full() > 0) {
                struct ip ip_hdr{};
                struct udphdr udp_hdr{};

                if(prepare_ip4_hdr(ip_hdr, it.second.get_packet_size(), it.first, usr_cds.dst_ip) < 0) exit(EXIT_FAILURE);
                if(prepare_udp_hdr(udp_hdr, 9999, usr_cds.dst_port, it.second.get_packet_size()) < 0) exit(EXIT_FAILURE);
                void* packet = pack_packet(ip_hdr, udp_hdr, it.second.get_packet(), it.second.get_packet_size());
                if(!packet) {
                    std::cerr << "Could not pack packet" << std::endl; exit(EXIT_FAILURE);
                }
 
                sin.sin_addr.s_addr = ip_hdr.ip_dst.s_addr;
                sendto (sd, packet, IP4_HDRLEN + UDP_HDRLEN + it.second.get_packet_size(), 0, (struct sockaddr *) &sin, sizeof (struct sockaddr));
                free(packet);
                it.second.set_packageSequence(it.second.get_packageSequence() +1);
                it.second.clear_filllevel();
            }
        }
    }

    return 0;
}

int
flow_writer_v6(user_credentials const& usr_cds, std::unordered_map<std::string, NetFlowBuilderv6>& inputv6)
{
    std::cout << ">> IP6 Writer Thread here..." << std::endl;
   
    /* --- Socket and Sendto preparement block --- */
    int sd = prepare_raw_socket(usr_cds.iface_name);
    if(sd < 0) exit(EXIT_FAILURE);
    struct sockaddr_in sin;
    memset(&sin, 0, sizeof(struct sockaddr_in));
    sin.sin_family = AF_INET; 
    
    while(!signal_caught) {
        for(auto& it : inputv6) {
            if(it.second.is_full() > 0) {
                struct ip ip_hdr{};
                struct udphdr udp_hdr{};

                if(prepare_ip4_hdr(ip_hdr, it.second.get_packet_size(), it.first, usr_cds.dst_ip) < 0) exit(EXIT_FAILURE);
                if(prepare_udp_hdr(udp_hdr, 9999, usr_cds.dst_port, it.second.get_packet_size()) < 0) exit(EXIT_FAILURE);
                void* packet = pack_packet(ip_hdr, udp_hdr, it.second.get_packet(), it.second.get_packet_size());
                if(!packet) {
                    std::cerr << "Could not pack packet" << std::endl; exit(EXIT_FAILURE);
                }
 
                sin.sin_addr.s_addr = ip_hdr.ip_dst.s_addr;
                sendto (sd, packet, IP4_HDRLEN + UDP_HDRLEN + it.second.get_packet_size(), 0, (struct sockaddr *) &sin, sizeof (struct sockaddr));
                free(packet);
                it.second.set_packageSequence(it.second.get_packageSequence() +1);
                it.second.clear_filllevel();
            }
        }
    }

    return 0;
}

/* ---  Processes user input;
        Starts workers for IP4, IP6 and "Other" --- */
/* --- TODO: - --- */
int
main(int argc, char** argv)
{
    if(argc != 2) {
        usage(argv[0]);
        exit(EXIT_FAILURE);
    }

    /* --- Setting up signal handler --- */
    struct sigaction sigact;
    sigact.sa_handler = signalhandler;
    if(sigaction(SIGINT, &sigact, 0) < 0) {
        std::cerr << "Could not set up signal handler." << std::endl;
        exit(EXIT_FAILURE);
    }
    /* --- End setting up signal handler --- */

    /* --- Setting up user credentials --- */
    user_credentials user_input{};

    if(setup_user_credentials(user_input, argv) < 0) exit(EXIT_FAILURE);
    print_userInput(user_input);
    /* --- End setting up user credentials --- */
    
    /* --- TESTING AREA --- */ 
    std::unordered_map<std::string, NetFlowBuilder>  test(30);
    std::unordered_map<std::string, NetFlowBuilderv6> testv6(30);
    std::thread t1(flow_consumer, user_input, std::ref(test), std::ref(testv6));
    std::thread t2(flow_writer, user_input, std::ref(test));
    std::thread t3(flow_writer_v6, user_input, std::ref(testv6));
    /* --- END TESTING AREA --- */

    /* --- Waiting for all worker to end and exiting after--- */
    t1.join(), t2.join(), t3.join();
    std::cout << "\n\r> All worker terminated. We are done here!" << std::endl;
    exit(EXIT_SUCCESS);
}
