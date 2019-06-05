#ifndef NETFLOW_BUILDER_HPP
#define NETFLOW_BUILDER_HPP

//#include <stdint.h>
#include <cstdint>
#include <string>
#include <vector>
#include "structs.hpp"

/* ---
TODO list:
    -
--- */

class NetFlowBuilder
{
    public:
        NetFlowBuilder();

        ~NetFlowBuilder();

        int init_memory();

        /* --- SETTER METHODS --- */
        int add_header(uint16_t _version, uint16_t _count, uint32_t _systemUptime, uint32_t _unixSeconds, 
            uint32_t _packageSequence, std::string _sourceID);

        int add_template(uint16_t _flowsetID, uint16_t _length, uint16_t _templateID, uint16_t _fieldCount,
            uint16_t _pkts = 0x0002, uint16_t _pktsLength = 0x0008, uint16_t _bytes = 0x0001, uint16_t _bytesLength = 0x0008,
            uint16_t _IP4SrcAddr = 0x0008, uint16_t _IP4SrcAddrLength = 0x0004, uint16_t _IP4DstAddr = 0x000c, 
            uint16_t _IP4DstAddrLength = 0x0004, uint16_t _InputSNMP = 0x000a, uint16_t _InputSNMPLength = 0x0004, 
            uint16_t _OutputSNMP = 0x000e, uint16_t _OutputSNMPLength = 0x0004, uint16_t _LastSwitched = 0x0015, 
            uint16_t _LastSwitchedLength = 0x0004, uint16_t _FirstSwitched = 0x0016, uint16_t _FirstSwitchedLength = 0x0004,
            uint16_t _L4SrcPort = 0x0007, uint16_t _L4SrcPortLength = 0x0002, uint16_t _L4DstPort = 0x000b,
            uint16_t _L4DstPortLength = 0x0002, uint16_t _SrcAS = 0x0010, uint16_t _SrcASLength = 0x0004, uint16_t _DstAS = 0x0011,
            uint16_t _DstASLength = 0x0004, uint16_t _BGPNextHop = 0x0012, uint16_t _BGPNextHopLength = 0x0004,
            uint16_t _SrcMask = 0x0009, uint16_t _SrcMaskLength = 0x0001, uint16_t _DstMask = 0x000d, uint16_t _DstMaskLength = 0x0001,
            uint16_t _Proto = 0x0004, uint16_t _ProtoLength = 0x0001, uint16_t _TCPFlags = 0x0006, uint16_t _TCPFlagsLength = 0x0001,
            uint16_t _IPToS = 0x0005, uint16_t _IPToSLength = 0x0001, uint16_t _Direction = 0x003d, uint16_t _DirectionLength = 0x0001,
            uint16_t _ForwardingStatus = 0x0059, uint16_t _ForwardingStatusLength = 0x0001, uint16_t _FlowSamplerID = 0x0030,
            uint16_t _FlowSamplerIDLength = 0x0002, uint16_t _IngressVRFID = 0x00ea, uint16_t _IngressVRFIDLength = 0x0004,
            uint16_t _EgressVRFID = 0x00eb, uint16_t _EgressVRFIDLength = 0x0004);

        int add_dataHeader(uint16_t _templateID, uint16_t _length);

        int add_data(uint64_t _pkts, uint64_t _bytes, std::string _IP4SrcAddr, std::string _IP4DstAddr, uint32_t _InputSNMP,
            uint32_t _OutputSNMP, uint32_t _LastSwitched, uint32_t _FirstSwitched, uint16_t _L4SrcPort, uint16_t _L4DstPort,
            uint32_t _SrcAS, uint32_t _DstAS, std::string _BGPNextHop, uint8_t _SrcMask, uint8_t _DstMask, uint8_t _Proto,
            uint8_t _TCPFlags, uint8_t _IPToS, uint8_t _Direction, uint8_t _ForwardingStatus, uint16_t _FlowSamplerID,
            uint32_t _IngressVRFID, uint32_t _EgressVRFID);

        void set_packageSequence(uint32_t);

        void clear_filllevel();

        /* --- GETTER METHODS --- */
        int is_full();
        uint16_t get_header_count();
        uint16_t get_template_length();
        uint16_t get_template_fieldCount();
        uint16_t get_dataHeader_length();
        uint32_t get_packageSequence();
        void* get_packet();
        size_t get_packet_size();
 
    private:
        struct Header {
            uint16_t version; // 0x0009
            uint16_t count;
            uint32_t systemUptime;
            uint32_t unixSeconds; // std::time(0)
            uint32_t packageSequence;
            uint32_t sourceID;
        };

        struct Template {
            uint16_t flowsetID; // 0x0000
            uint16_t length; // 0x0064
            uint16_t templateID; // 0x0104
            uint16_t fieldCount; // 0x0017
            uint16_t pkts; // 0x0002
            uint16_t pktsLength; // 0x0008
            uint16_t bytes; // 0x0001
            uint16_t bytesLength; // 0x0008
            uint16_t IP4SrcAddr; // 0x0008
            uint16_t IP4SrcAddrLength; // 0x0004
            uint16_t IP4DstAddr; // 0x000c
            uint16_t IP4DstAddrLength; // 0x0004
            uint16_t InputSNMP; // 0x000a; corresponds to SrcIF in goflow
            uint16_t InputSNMPLength; // 0x0004
            uint16_t OutputSNMP; // 0x000e; corresponds to DstIF in goflow
            uint16_t OutputSNMPLength; // 0x0004
            uint16_t LastSwitched; // 0x0015; corresponds to TimeRecvd in goflow
            uint16_t LastSwitchedLength; // 0x0004 in NetFlow v9, 8byte in goflow
            uint16_t FirstSwitched; // 0x0016; corresponds to TimeFlow in goflow
            uint16_t FirstSwitchedLength; // 0x0004 in NetFlow v9, 8byte in goflow
            uint16_t L4SrcPort; // 0x0007
            uint16_t L4SrcPortLength; // 0x0002
            uint16_t L4DstPort; // 0x000b
            uint16_t L4DstPortLength; // 0x0002
            uint16_t SrcAS; // 0x0010
            uint16_t SrcASLength; // 0x0004
            uint16_t DstAS; // 0x0011
            uint16_t DstASLength; // 0x0004
            uint16_t BGPNextHop; // 0x0012; corresponds to NextHop in goflow
            uint16_t BGPNextHopLength; // 0x0004
            uint16_t SrcMask; // 0x0009; corresponds to SrcNet in goflow
            uint16_t SrcMaskLength; // 0x0001;
            uint16_t DstMask; // 0x000d; corresponds to DstNet in goflow
            uint16_t DstMaskLength; // 0x0001
            uint16_t Proto; // 0x0004
            uint16_t ProtoLength; // 0x0001
            uint16_t TCPFlags; // 0x0006
            uint16_t TCPFlagsLength; // 0x0001
            uint16_t IPToS; // 0x0005
            uint16_t IPToSLength; // 0x0001
            uint16_t Direction; // 0x003d
            uint16_t DirectionLength; // 0x0001
            uint16_t ForwardingStatus; // 0x0059
            uint16_t ForwardingStatusLength; // 0x0001
            uint16_t FlowSamplerID; // 0x0030
            uint16_t FlowSamplerIDLength; // 0x0002
            uint16_t IngressVRFID; // 0x00ea
            uint16_t IngressVRFIDLength; // 0x0004
            uint16_t EgressVRFID; // 0x00eb
            uint16_t EgressVRFIDLength; // 0x0004
        };

        struct DataHeader {
            uint16_t templateID; // same as Template.flowsetID
            uint16_t length; // length of the whole Data struct object incl. templateID and length fields
        };

        #pragma pack(push)
        #pragma pack(1)
        struct Data {
            uint64_t pkts;
            uint64_t bytes;
            uint32_t IP4SrcAddr;
            uint32_t IP4DstAddr;
            uint32_t InputSNMP;
            uint32_t OutputSNMP;
            uint32_t LastSwitched;
            uint32_t FirstSwitched;
            uint16_t L4SrcPort;
            uint16_t L4DstPort;
            uint32_t SrcAS;
            uint32_t DstAS;
            uint32_t BGPNextHop;
            uint8_t SrcMask; 
            uint8_t DstMask;
            uint8_t Proto;
            uint8_t TCPFlags;
            uint8_t IPToS;
            uint8_t Direction;
            uint8_t ForwardingStatus;
            uint16_t FlowSamplerID;
            uint32_t IngressVRFID;
            uint32_t EgressVRFID;
        };
        #pragma pack(pop)

        /* --- GENERAL METHODS --- */
        size_t calc_needed_memory();
        void set_pointer();
        
        static const uint16_t capacity = 18;
        uint16_t filllevel;
        void* packet_ptr;
        void* header_ptr;
        void* template_ptr;
        void* dataHeader_ptr;
        void* data_ptr;
        void* currentPosition_ptr;
};

/* --- TODO: calculate the max amount of v6 flows that fits into a packet
---*/

class NetFlowBuilderv6
{
    public:
        NetFlowBuilderv6();

        ~NetFlowBuilderv6();

        int init_memory();

        /* --- SETTER METHODS --- */
        int add_header(uint16_t _version, uint16_t _count, uint32_t _systemUptime, uint32_t _unixSeconds, 
            uint32_t _packageSequence, std::string _sourceID);

        int add_template(uint16_t _flowsetID, uint16_t _length, uint16_t _templateID, uint16_t _fieldCount,
            uint16_t _pkts = 0x0002, uint16_t _pktsLength = 0x0008, uint16_t _bytes = 0x0001, uint16_t _bytesLength = 0x0008,
            uint16_t _IP6SrcAddr = 0x001b, uint16_t _IP6SrcAddrLength = 0x0010, uint16_t _IP6DstAddr = 0x001c, 
            uint16_t _IP6DstAddrLength = 0x0010, uint16_t _InputSNMP = 0x000a, uint16_t _InputSNMPLength = 0x0004,
            uint16_t _OutputSNMP = 0x000e, uint16_t _OutputSNMPLength = 0x0004, uint16_t _FirstSwitched = 0x0016,
            uint16_t _FirstSwitchedLength = 0x0004, uint16_t _LastSwitched = 0x0015, uint16_t _LastSwitchedLength = 0x0004,
            uint16_t _FlowLabel = 0x001f, uint16_t _FlowLabelLength = 0x0004, uint16_t _IP6OptionHeaders = 0x0040,
            uint16_t _IP6OptionHeadersLength = 0x0004, uint16_t _L4SrcPort = 0x0007, uint16_t _L4SrcPortLength = 0x0002, 
            uint16_t _L4DstPort = 0x000b, uint16_t _L4DstPortLength = 0x0002, uint16_t _SrcAS = 0x0010, 
            uint16_t _SrcASLength = 0x0004, uint16_t _DstAS = 0x0011, uint16_t _DstASLength = 0x0004,
            uint16_t _BGPIP6NextHop = 0x003f, uint16_t _BGPIP6NextHopLength = 0x0010, uint16_t _IP6DstMask = 0x001e,
            uint16_t _IP6DstMaskLength = 0x0001, uint16_t _IP6SrcMask = 0x001d, uint16_t _IP6SrcMaskLength = 0x0001,
            uint16_t _Proto = 0x0004, uint16_t _ProtoLength = 0x0001, uint16_t _TCPFlags = 0x0006, uint16_t _TCPFlagsLength = 0x0001,
            uint16_t _IPToS = 0x0005, uint16_t _IPToSLength = 0x0001, uint16_t _Direction = 0x003d, uint16_t _DirectionLength = 0x0001,
            uint16_t _ForwardingStatus = 0x0059, uint16_t _ForwardingStatusLength = 0x0001, uint16_t _FlowSamplerID = 0x0030,
            uint16_t _FlowSamplerIDLength = 0x0002, uint16_t _IngressVRFID = 0x00ea, uint16_t _IngressVRFIDLength = 0x0004,
            uint16_t _EgressVRFID = 0x00eb, uint16_t _EgressVRFIDLength = 0x0004);

        int add_dataHeader(uint16_t _templateID, uint16_t _length);

        int add_data(uint64_t _pkts, uint64_t _bytes, std::string _IP6SrcAddr, std::string _IP6DstAddr, uint32_t _InputSNMP, 
            uint32_t _OutputSNMP, uint32_t _FirstSwitched, uint32_t _LastSwitched, uint32_t _FlowLabel, 
            uint32_t _IP6OptionHeaders, uint16_t _L4SrcPort, uint16_t _L4DstPort, uint32_t _SrcAS, uint32_t _DstAS, 
            std::string _BGPIP6NextHop, uint8_t _IP6DstMask, uint8_t _IP6SrcMask, uint8_t _Proto, uint8_t _TCPFlags, uint8_t _IPToS,
            uint8_t _Direction, uint8_t _ForwardingStatus, uint16_t _FlowSamplerID, uint32_t _IngressVRFID, uint32_t _EgressVRFID);

        void set_packageSequence(uint32_t);

        void clear_filllevel();

        /* --- GETTER METHODS --- */
        int is_full();
        uint16_t get_header_count();
        uint16_t get_template_length();
        uint16_t get_template_fieldCount();
        uint16_t get_dataHeader_length();
        uint32_t get_packageSequence();
        void* get_packet();
        size_t get_packet_size();

    private:
        struct Header {
            uint16_t version; // 0x0009
            uint16_t count;
            uint32_t systemUptime;
            uint32_t unixSeconds; // std::time(0)
            uint32_t packageSequence;
            uint32_t sourceID;
        };

        struct Template {
            uint16_t flowsetID; // 0x0000
            uint16_t length; // 0x0064
            uint16_t templateID; // 0x010a
            uint16_t fieldCount; // 0x0017
            uint16_t pkts; // 0x0002
            uint16_t pktsLength; // 0x0008
            uint16_t bytes; // 0x0001
            uint16_t bytesLength; // 0x0008
            uint16_t IP6SrcAddr; // 0x001b
            uint16_t IP6SrcAddrLength; // 0x0010
            uint16_t IP6DstAddr; // 0x001c
            uint16_t IP6DstAddrLength; // 0x0010
            uint16_t InputSNMP; // 0x000a; corresponds to SrcIF in goflow
            uint16_t InputSNMPLength; // 0x0004
            uint16_t OutputSNMP; // 0x000e; corresponds to DstIF in goflow
            uint16_t OutputSNMPLength; // 0x0004
            uint16_t FirstSwitched; // 0x0015; corresponds to TimeRecvd in goflow
            uint16_t FirstSwitchedLength; // 0x0004 in NetFlow v9, 8byte in goflow
            uint16_t LastSwitched; // 0x0016; corresponds to TimeFlow in goflow
            uint16_t LastSwitchedLength; // 0x0004 in NetFlow v9, 8byte in goflow
            uint16_t FlowLabel;
            uint16_t FlowLabelLength;
            uint16_t IP6OptionHeaders;
            uint16_t IP6OptionHeadersLength;
            uint16_t L4SrcPort; // 0x0007
            uint16_t L4SrcPortLength; // 0x0002
            uint16_t L4DstPort; // 0x000b
            uint16_t L4DstPortLength; // 0x0002
            uint16_t SrcAS; // 0x0010
            uint16_t SrcASLength; // 0x0004
            uint16_t DstAS; // 0x0011
            uint16_t DstASLength; // 0x0004
            uint16_t BGPIP6NextHop;
            uint16_t BGPIP6NextHopLength;
            uint16_t IP6DstMask;
            uint16_t IP6DstMaskLength;
            uint16_t IP6SrcMask;
            uint16_t IP6SrcMaskLength;
            uint16_t Proto; // 0x0004
            uint16_t ProtoLength; // 0x0001
            uint16_t TCPFlags; // 0x0006
            uint16_t TCPFlagsLength; // 0x0001
            uint16_t IPToS; // 0x0005
            uint16_t IPToSLength; // 0x0001
            uint16_t Direction; // 0x003d
            uint16_t DirectionLength; // 0x0001
            uint16_t ForwardingStatus; // 0x0059
            uint16_t ForwardingStatusLength; // 0x0001
            uint16_t FlowSamplerID; // 0x0030
            uint16_t FlowSamplerIDLength; // 0x0002
            uint16_t IngressVRFID; // 0x00ea
            uint16_t IngressVRFIDLength; // 0x0004
            uint16_t EgressVRFID; // 0x00eb
            uint16_t EgressVRFIDLength; // 0x0004
        };

        struct DataHeader {
            uint16_t templateID; // same as Template.flowsetID
            uint16_t length; // length of the whole Data struct object incl. templateID and length fields           
        };

        #pragma pack(push)
        #pragma pack(1)
        struct Data {
            uint64_t pkts;
            uint64_t bytes;
            uint128_t IP6SrcAddr;
            uint128_t IP6DstAddr;
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
            uint128_t BGPIP6NextHop;
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
        #pragma pack(pop)

        /* --- GENERAL METHODS --- */
        size_t calc_needed_memory();
        void set_pointer();

        static const uint16_t capacity = 11;
        uint16_t filllevel;
        void* packet_ptr;
        void* header_ptr;
        void* template_ptr;
        void* dataHeader_ptr;
        void* data_ptr;
        void* currentPosition_ptr;
};

#endif
