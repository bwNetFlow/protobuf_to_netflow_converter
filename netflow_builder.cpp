#include "netflow_builder.hpp"
#include <sstream>
#include <arpa/inet.h>
#include <iostream>
#include <cstdlib>
#include <string.h>
#include <endian.h>

/* --- TODO:    Fix current_ptr calculation in both classes --- */

/* --------------------------------------------------------------- */
/* ------------------------- IPv4 BUILDER ------------------------ */
/* --------------------------------------------------------------- */

/* --- TODO:   -
--- */

NetFlowBuilder::NetFlowBuilder() : filllevel{0}, packet_ptr{NULL}, header_ptr{NULL},
    template_ptr{NULL}, dataHeader_ptr{NULL}, data_ptr{NULL}, currentPosition_ptr{NULL} {}

NetFlowBuilder::~NetFlowBuilder() 
{
    free(packet_ptr);
}

/* -- Returns 1 on Success; Returns -1 on Error -- */
int
NetFlowBuilder::init_memory()
{
    size_t needed_space = calc_needed_memory();
    packet_ptr = malloc(needed_space);
    if(!packet_ptr) {
        return -1;    
    }
    set_pointer();
    return 1;
}

/* --- SETTER METHODS ---*/
int 
NetFlowBuilder::add_header(uint16_t _version, uint16_t _count, uint32_t _systemUptime, uint32_t _unixSeconds, 
    uint32_t _packageSequence, std::string _sourceID)
{
    Header tmp_header{};
    tmp_header.version = htons(_version);
    tmp_header.count = htons(_count);
    tmp_header.systemUptime = htonl(_systemUptime);
    tmp_header.unixSeconds = htonl(_unixSeconds);
    tmp_header.packageSequence = htonl(_packageSequence);

    memcpy((void*) &tmp_header.sourceID, (void*) _sourceID.c_str(), sizeof(tmp_header.sourceID));
    //tmp_header.sourceID = htonl(_sourceID);

    memcpy((void*) header_ptr, (void*) &tmp_header, sizeof(Header));

    currentPosition_ptr = header_ptr;

    return 1;
}


int 
NetFlowBuilder::add_template(uint16_t _flowsetID, uint16_t _length, uint16_t _templateID, uint16_t _fieldCount,
    uint16_t _pkts, uint16_t _pktsLength, uint16_t _bytes, uint16_t _bytesLength,
    uint16_t _IP4SrcAddr, uint16_t _IP4SrcAddrLength, uint16_t _IP4DstAddr,
    uint16_t _IP4DstAddrLength, uint16_t _InputSNMP, uint16_t _InputSNMPLength,
    uint16_t _OutputSNMP, uint16_t _OutputSNMPLength, uint16_t _LastSwitched, 
    uint16_t _LastSwitchedLength, uint16_t _FirstSwitched, uint16_t _FirstSwitchedLength,
    uint16_t _L4SrcPort, uint16_t _L4SrcPortLength, uint16_t _L4DstPort,
    uint16_t _L4DstPortLength, uint16_t _SrcAS, uint16_t _SrcASLength, uint16_t _DstAS,
    uint16_t _DstASLength, uint16_t _BGPNextHop, uint16_t _BGPNextHopLength,
    uint16_t _SrcMask, uint16_t _SrcMaskLength, uint16_t _DstMask, uint16_t _DstMaskLength,
    uint16_t _Proto, uint16_t _ProtoLength, uint16_t _TCPFlags, uint16_t _TCPFlagsLength,
    uint16_t _IPToS, uint16_t _IPToSLength, uint16_t _Direction, uint16_t _DirectionLength,
    uint16_t _ForwardingStatus, uint16_t _ForwardingStatusLength, uint16_t _FlowSamplerID,
    uint16_t _FlowSamplerIDLength, uint16_t _IngressVRFID, uint16_t _IngressVRFIDLength,
    uint16_t _EgressVRFID, uint16_t _EgressVRFIDLength)
{
    Template tmp_template{};
    tmp_template.flowsetID = htons(_flowsetID);
    tmp_template.length = htons(_length);
    tmp_template.templateID = htons(_templateID);
    tmp_template.fieldCount = htons(_fieldCount);
    tmp_template.pkts = htons(_pkts);
    tmp_template.pktsLength = htons(_pktsLength);
    tmp_template.bytes = htons(_bytes);
    tmp_template.bytesLength = htons(_bytesLength);
    tmp_template.IP4SrcAddr = htons(_IP4SrcAddr);
    tmp_template.IP4SrcAddrLength = htons(_IP4SrcAddrLength);
    tmp_template.IP4DstAddr = htons(_IP4DstAddr);
    tmp_template.IP4DstAddrLength = htons(_IP4DstAddrLength);
    tmp_template.InputSNMP = htons(_InputSNMP);
    tmp_template.InputSNMPLength = htons(_InputSNMPLength);
    tmp_template.OutputSNMP = htons(_OutputSNMP);
    tmp_template.OutputSNMPLength = htons(_OutputSNMPLength);
    tmp_template.LastSwitched = htons(_LastSwitched);
    tmp_template.LastSwitchedLength = htons(_LastSwitchedLength);
    tmp_template.FirstSwitched = htons(_FirstSwitched);
    tmp_template.FirstSwitchedLength = htons(_FirstSwitchedLength);
    tmp_template.L4SrcPort = htons(_L4SrcPort);
    tmp_template.L4SrcPortLength = htons(_L4SrcPortLength);
    tmp_template.L4DstPort = htons(_L4DstPort);
    tmp_template.L4DstPortLength = htons(_L4DstPortLength);
    tmp_template.SrcAS = htons(_SrcAS);
    tmp_template.SrcASLength = htons(_SrcASLength);
    tmp_template.DstAS = htons(_DstAS);
    tmp_template.DstASLength = htons(_DstASLength);
    tmp_template.BGPNextHop = htons(_BGPNextHop);
    tmp_template.BGPNextHopLength = htons(_BGPNextHopLength);
    tmp_template.SrcMask = htons(_SrcMask);
    tmp_template.SrcMaskLength = htons(_SrcMaskLength);
    tmp_template.DstMask = htons(_DstMask);
    tmp_template.DstMaskLength = htons(_DstMaskLength);
    tmp_template.Proto = htons(_Proto);
    tmp_template.ProtoLength = htons(_ProtoLength);
    tmp_template.TCPFlags = htons(_TCPFlags);
    tmp_template.TCPFlagsLength = htons(_TCPFlagsLength);
    tmp_template.IPToS = htons(_IPToS);
    tmp_template.IPToSLength = htons(_IPToSLength);
    tmp_template.Direction = htons(_Direction);
    tmp_template.DirectionLength = htons(_DirectionLength);
    tmp_template.ForwardingStatus = htons(_ForwardingStatus);
    tmp_template.ForwardingStatusLength = htons(_ForwardingStatusLength);
    tmp_template.FlowSamplerID = htons(_FlowSamplerID);
    tmp_template.FlowSamplerIDLength = htons(_FlowSamplerIDLength);
    tmp_template.IngressVRFID = htons(_IngressVRFID);
    tmp_template.IngressVRFIDLength = htons(_IngressVRFIDLength);
    tmp_template.EgressVRFID = htons(_EgressVRFID);
    tmp_template.EgressVRFIDLength = htons(_EgressVRFIDLength);

    memcpy((void*) template_ptr, (void*) &tmp_template, sizeof(Template));

    currentPosition_ptr = template_ptr;

    return 1;
}

int 
NetFlowBuilder::add_dataHeader(uint16_t _templateID, uint16_t _length)
{
    DataHeader tmp_dataHeader{};
    tmp_dataHeader.templateID = htons(_templateID);
    tmp_dataHeader.length = htons(_length);

    memcpy((void*) dataHeader_ptr, (void*) &tmp_dataHeader, sizeof(DataHeader));

    currentPosition_ptr = dataHeader_ptr;

    return 1;
}

/* -- Returns 0 if max capacity is reached; Returns 1 on Success --*/
int
NetFlowBuilder::add_data(uint64_t _pkts, uint64_t _bytes, std::string _IP4SrcAddr, std::string _IP4DstAddr, uint32_t _InputSNMP,
    uint32_t _OutputSNMP, uint32_t _LastSwitched, uint32_t _FirstSwitched, uint16_t _L4SrcPort, uint16_t _L4DstPort,
    uint32_t _SrcAS, uint32_t _DstAS, std::string _BGPNextHop, uint8_t _SrcMask, uint8_t _DstMask, uint8_t _Proto,
    uint8_t _TCPFlags, uint8_t _IPToS, uint8_t _Direction, uint8_t _ForwardingStatus,
    uint16_t _FlowSamplerID, uint32_t _IngressVRFID, uint32_t _EgressVRFID)
{
    if(capacity <= filllevel) return 0;

    Data tmp_data{};
    tmp_data.pkts = htobe64(_pkts);
    tmp_data.bytes = htobe64(_bytes);
    memcpy((void*) &tmp_data.IP4SrcAddr, (void*) _IP4SrcAddr.c_str(), sizeof(tmp_data.IP4SrcAddr));
    memcpy((void*) &tmp_data.IP4DstAddr, (void*) _IP4DstAddr.c_str(), sizeof(tmp_data.IP4DstAddr));
    tmp_data.InputSNMP = htonl(_InputSNMP);
    tmp_data.OutputSNMP = htonl(_OutputSNMP);
    tmp_data.LastSwitched = htonl(_LastSwitched);
    tmp_data.FirstSwitched = htonl(_FirstSwitched);
    tmp_data.L4SrcPort = htons(_L4SrcPort);
    tmp_data.L4DstPort = htons(_L4DstPort);
    tmp_data.SrcAS = htonl(_SrcAS);
    tmp_data.DstAS = htonl(_DstAS);
    memcpy((void*) &tmp_data.BGPNextHop, (void*) _BGPNextHop.c_str(), sizeof(tmp_data.BGPNextHop));
    tmp_data.SrcMask = _SrcMask;
    tmp_data.DstMask = _DstMask;
    tmp_data.Proto = _Proto;
    tmp_data.TCPFlags = _TCPFlags;
    tmp_data.IPToS = _IPToS;
    tmp_data.Direction = _Direction;
    tmp_data.ForwardingStatus = _ForwardingStatus;
    tmp_data.FlowSamplerID = htons(_FlowSamplerID);
    tmp_data.IngressVRFID = htonl(_IngressVRFID);
    tmp_data.EgressVRFID = htonl(_EgressVRFID);

    memcpy((void*) ((char*)data_ptr + filllevel*sizeof(Data)), (void*) &tmp_data, sizeof(Data));

    ++filllevel;
    currentPosition_ptr = (void*) ((char*) data_ptr + filllevel*sizeof(Data));

    return 1;
}

void
NetFlowBuilder::set_packageSequence(uint32_t new_value)
{
    if(!header_ptr) ;
    else {
        uint32_t tmp_new = htonl(new_value);
        memcpy((char*)header_ptr+2*sizeof(uint16_t)+2*sizeof(uint32_t), &tmp_new, sizeof(uint32_t));
    }
}

void
NetFlowBuilder::set_sysUptime(uint32_t new_value)
{
    if(!header_ptr) ;
    else {
        uint32_t tmp_new = htonl(new_value);
        memcpy((char*)header_ptr+2*sizeof(uint16_t), &tmp_new, sizeof(uint32_t));
    }
}

void
NetFlowBuilder::set_unixSeconds(uint32_t new_value)
{
    if(!header_ptr) ;
    else {
        uint32_t tmp_new = htonl(new_value);
        memcpy((char*)header_ptr+2*sizeof(uint16_t)+1*sizeof(uint32_t), &tmp_new, sizeof(uint32_t));
    }
}

void
NetFlowBuilder::clear_filllevel()
{
    filllevel = 0;
}

/* --- GETTER METHODS ---*/

/* --- Returns 1 if full; else 0 --- */
int
NetFlowBuilder::is_full()
{
    if(capacity <= filllevel) return 1;
    else return 0;
}

uint16_t 
NetFlowBuilder::get_header_count()
{
    return capacity + 1; // capacity defines the number of data records + one template record
}

uint16_t
NetFlowBuilder::get_template_length()
{
    return sizeof(Template);
}

uint16_t
NetFlowBuilder::get_template_fieldCount()
{
    uint16_t nmbr_of_elements = sizeof(Template) / sizeof(uint16_t);
    uint16_t nmbr_without_static_fields = nmbr_of_elements - 4; // There are always 4 static fields
    uint16_t nmbr_of_fields = nmbr_without_static_fields / 2; // There is alaways a field type and a field length name per field
    return nmbr_of_fields;
}

uint16_t 
NetFlowBuilder::get_dataHeader_length()
{
    return (sizeof(DataHeader) + (capacity*sizeof(Data)));
}

uint32_t
NetFlowBuilder::get_packageSequence()
{
    if(!header_ptr) return 0;
    else {
        uint32_t tmp_packageSequence;
        tmp_packageSequence = ntohl(*(uint32_t*)((char*)header_ptr+2*sizeof(uint16_t)+2*sizeof(uint32_t)));
        return tmp_packageSequence;
    }
}

void*
NetFlowBuilder::get_packet() 
{
    return packet_ptr;
}

size_t
NetFlowBuilder::get_packet_size()
{
   return (sizeof(Header) + sizeof (Template) + sizeof (DataHeader) + (capacity*sizeof(Data)));
}

/* --- GENERAL METHODS --- */
size_t
NetFlowBuilder::calc_needed_memory()
{
    /*
    std::cout << "Header: " << sizeof(Header) << std::endl;
    std::cout << "Template: " << sizeof(Template) << std::endl;
    std::cout << "DataHeader: " << sizeof(DataHeader) << std::endl;
    std::cout << "Data: " << sizeof(Data) << std::endl;
    */

    return (sizeof(Header) + sizeof (Template) + sizeof (DataHeader) + (capacity*sizeof(Data)));
}

void
NetFlowBuilder::set_pointer()
{
    header_ptr = packet_ptr;
    template_ptr = (void*)((char*) header_ptr + sizeof(Header));
    dataHeader_ptr = (void*)((char*) template_ptr + sizeof(Template));
    data_ptr = (void*)((char*) dataHeader_ptr + sizeof(DataHeader));
    currentPosition_ptr = packet_ptr;
}

/* --------------------------------------------------------------- */
/* ------------------------- IPv6 BUILDER ------------------------ */
/* --------------------------------------------------------------- */

/* --- TODO: -
 --- */

NetFlowBuilderv6::NetFlowBuilderv6() : filllevel{0}, packet_ptr{NULL}, header_ptr{NULL},
    template_ptr{NULL}, dataHeader_ptr{NULL}, data_ptr{NULL}, currentPosition_ptr{NULL} {}

NetFlowBuilderv6::~NetFlowBuilderv6()
{
        free(packet_ptr);
}

/* -- Returns 1 on Success; Returns -1 on Error -- */
int
NetFlowBuilderv6::init_memory()
{
    size_t needed_space = calc_needed_memory();
    packet_ptr = malloc(needed_space);
    if(!packet_ptr) {
        return -1;
    }
    set_pointer();
    return 1;
}

/* --- SETTER METHODS ---*/
int 
NetFlowBuilderv6::add_header(uint16_t _version, uint16_t _count, uint32_t _systemUptime, uint32_t _unixSeconds, 
    uint32_t _packageSequence, std::string _sourceID)
{
    Header tmp_header{};
    tmp_header.version = htons(_version);
    tmp_header.count = htons(_count);
    tmp_header.systemUptime = htonl(_systemUptime);
    tmp_header.unixSeconds = htonl(_unixSeconds);
    tmp_header.packageSequence = htonl(_packageSequence);

    memcpy((void*) &tmp_header.sourceID, (void*) _sourceID.c_str(), sizeof(tmp_header.sourceID));
    //tmp_header.sourceID = htonl(_sourceID);

    memcpy((void*) header_ptr, (void*) &tmp_header, sizeof(Header));

    currentPosition_ptr = header_ptr;

    return 1;
}

int 
NetFlowBuilderv6::add_template(uint16_t _flowsetID, uint16_t _length, uint16_t _templateID, uint16_t _fieldCount,
    uint16_t _pkts, uint16_t _pktsLength, uint16_t _bytes, uint16_t _bytesLength, 
    uint16_t _IP6SrcAddr, uint16_t _IP6SrcAddrLength, uint16_t _IP6DstAddr, uint16_t _IP6DstAddrLength, 
    uint16_t _InputSNMP, uint16_t _InputSNMPLength, uint16_t _OutputSNMP, uint16_t _OutputSNMPLength, 
    uint16_t _FirstSwitched, uint16_t _FirstSwitchedLength, uint16_t _LastSwitched, uint16_t _LastSwitchedLength,
    uint16_t _FlowLabel, uint16_t _FlowLabelLength, uint16_t _IP6OptionHeaders, uint16_t _IP6OptionHeadersLength,
    uint16_t _L4SrcPort, uint16_t _L4SrcPortLength, uint16_t _L4DstPort, uint16_t _L4DstPortLength,
    uint16_t _SrcAS, uint16_t _SrcASLength, uint16_t _DstAS, uint16_t _DstASLength, uint16_t _BGPIP6NextHop, 
    uint16_t _BGPIP6NextHopLength, uint16_t _IP6DstMask, uint16_t _IP6DstMaskLength, uint16_t _IP6SrcMask, 
    uint16_t _IP6SrcMaskLength, uint16_t _Proto, uint16_t _ProtoLength, uint16_t _TCPFlags, uint16_t _TCPFlagsLength,
    uint16_t _IPToS, uint16_t _IPToSLength, uint16_t _Direction, uint16_t _DirectionLength,
    uint16_t _ForwardingStatus, uint16_t _ForwardingStatusLength, uint16_t _FlowSamplerID,
    uint16_t _FlowSamplerIDLength, uint16_t _IngressVRFID, uint16_t _IngressVRFIDLength,
    uint16_t _EgressVRFID, uint16_t _EgressVRFIDLength)
{
    Template tmp_template{};
    tmp_template.flowsetID = htons(_flowsetID);
    tmp_template.length = htons(_length);
    tmp_template.templateID = htons(_templateID);
    tmp_template.fieldCount = htons(_fieldCount);
    tmp_template.pkts = htons(_pkts);
    tmp_template.pktsLength = htons(_pktsLength);
    tmp_template.bytes = htons(_bytes);
    tmp_template.bytesLength = htons(_bytesLength);
    tmp_template.IP6SrcAddr = htons(_IP6SrcAddr);
    tmp_template.IP6SrcAddrLength = htons(_IP6SrcAddrLength);
    tmp_template.IP6DstAddr = htons(_IP6DstAddr);
    tmp_template.IP6DstAddrLength = htons(_IP6DstAddrLength);
    tmp_template.InputSNMP = htons(_InputSNMP);
    tmp_template.InputSNMPLength = htons(_InputSNMPLength);
    tmp_template.OutputSNMP = htons(_OutputSNMP);
    tmp_template.OutputSNMPLength = htons(_OutputSNMPLength);
    tmp_template.FirstSwitched = htons(_FirstSwitched);
    tmp_template.FirstSwitchedLength = htons(_FirstSwitchedLength);
    tmp_template.LastSwitched = htons(_LastSwitched);
    tmp_template.LastSwitchedLength = htons(_LastSwitchedLength);
    tmp_template.FlowLabel = htons(_FlowLabel);
    tmp_template.FlowLabelLength = htons(_FlowLabelLength);
    tmp_template.IP6OptionHeaders = htons(_IP6OptionHeaders);
    tmp_template.IP6OptionHeadersLength = htons(_IP6OptionHeadersLength);
    tmp_template.L4SrcPort = htons(_L4SrcPort);
    tmp_template.L4SrcPortLength = htons(_L4SrcPortLength);
    tmp_template.L4DstPort = htons(_L4DstPort);
    tmp_template.L4DstPortLength = htons(_L4DstPortLength);
    tmp_template.SrcAS = htons(_SrcAS);
    tmp_template.SrcASLength = htons(_SrcASLength);
    tmp_template.DstAS = htons(_DstAS);
    tmp_template.DstASLength = htons(_DstASLength);
    tmp_template.BGPIP6NextHop = htons(_BGPIP6NextHop);
    tmp_template.BGPIP6NextHopLength = htons(_BGPIP6NextHopLength);
    tmp_template.IP6DstMask = htons(_IP6DstMask);
    tmp_template.IP6DstMaskLength = htons(_IP6DstMaskLength);
    tmp_template.IP6SrcMask = htons(_IP6SrcMask);
    tmp_template.IP6SrcMaskLength = htons(_IP6SrcMaskLength);
    tmp_template.Proto = htons(_Proto);
    tmp_template.ProtoLength = htons(_ProtoLength);
    tmp_template.TCPFlags = htons(_TCPFlags);
    tmp_template.TCPFlagsLength = htons(_TCPFlagsLength);
    tmp_template.IPToS = htons(_IPToS);
    tmp_template.IPToSLength = htons(_IPToSLength);
    tmp_template.Direction = htons(_Direction);
    tmp_template.DirectionLength = htons(_DirectionLength);
    tmp_template.ForwardingStatus = htons(_ForwardingStatus);
    tmp_template.ForwardingStatusLength = htons(_ForwardingStatusLength);
    tmp_template.FlowSamplerID = htons(_FlowSamplerID);
    tmp_template.FlowSamplerIDLength = htons(_FlowSamplerIDLength);
    tmp_template.IngressVRFID = htons(_IngressVRFID);
    tmp_template.IngressVRFIDLength = htons(_IngressVRFIDLength);
    tmp_template.EgressVRFID = htons(_EgressVRFID);
    tmp_template.EgressVRFIDLength = htons(_EgressVRFIDLength);

    memcpy((void*) template_ptr, (void*) &tmp_template, sizeof(Template));

    currentPosition_ptr = template_ptr;

    return 1;
}

int 
NetFlowBuilderv6::add_dataHeader(uint16_t _templateID, uint16_t _length)
{
    DataHeader tmp_dataHeader{};
    tmp_dataHeader.templateID = htons(_templateID);
    tmp_dataHeader.length = htons(_length);

    memcpy((void*) dataHeader_ptr, (void*) &tmp_dataHeader, sizeof(DataHeader));

    currentPosition_ptr = dataHeader_ptr;

    return 1;
}

/* -- Returns 0 if max capacity is reached; Returns 1 on Success --*/
int
NetFlowBuilderv6::add_data(uint64_t _pkts, uint64_t _bytes, std::string _IP6SrcAddr, std::string _IP6DstAddr, uint32_t _InputSNMP, 
    uint32_t _OutputSNMP, uint32_t _FirstSwitched, uint32_t _LastSwitched, uint32_t _FlowLabel, 
    uint32_t _IP6OptionHeaders, uint16_t _L4SrcPort, uint16_t _L4DstPort, uint32_t _SrcAS, uint32_t _DstAS, 
    std::string _BGPIP6NextHop, uint8_t _IP6DstMask, uint8_t _IP6SrcMask, uint8_t _Proto, uint8_t _TCPFlags, uint8_t _IPToS,
    uint8_t _Direction, uint8_t _ForwardingStatus, uint16_t _FlowSamplerID, uint32_t _IngressVRFID, uint32_t _EgressVRFID)
{
    if(capacity <= filllevel) return 0;

    Data tmp_data{};
    tmp_data.pkts = htobe64(_pkts);
    tmp_data.bytes = htobe64(_bytes);
    memcpy((void*) &tmp_data.IP6SrcAddr, (void*) _IP6SrcAddr.c_str(), sizeof(tmp_data.IP6SrcAddr)); 
    memcpy((void*) &tmp_data.IP6DstAddr, (void*) _IP6DstAddr.c_str(), sizeof(tmp_data.IP6DstAddr));
    tmp_data.InputSNMP = htonl(_InputSNMP);
    tmp_data.OutputSNMP = htonl(_OutputSNMP);
    tmp_data.FirstSwitched = htonl(_FirstSwitched);
    tmp_data.LastSwitched = htonl(_LastSwitched);
    tmp_data.FlowLabel = htonl(_FlowLabel);
    tmp_data.IP6OptionHeaders = htonl(_IP6OptionHeaders);
    tmp_data.L4SrcPort = htons(_L4SrcPort);
    tmp_data.L4DstPort = htons(_L4DstPort);
    tmp_data.SrcAS = htonl(_SrcAS);
    tmp_data.DstAS = htonl(_DstAS);
    memcpy((void*) &tmp_data.BGPIP6NextHop, (void*) _BGPIP6NextHop.c_str(), sizeof(tmp_data.BGPIP6NextHop));
    tmp_data.IP6DstMask = _IP6DstMask;
    tmp_data.IP6SrcMask = _IP6SrcMask;
    tmp_data.Proto = _Proto;
    tmp_data.TCPFlags = _TCPFlags;
    tmp_data.IPToS = _IPToS;
    tmp_data.Direction = _Direction;
    tmp_data.ForwardingStatus = _ForwardingStatus;
    tmp_data.FlowSamplerID = htons(_FlowSamplerID);
    tmp_data.IngressVRFID = htonl(_IngressVRFID);
    tmp_data.EgressVRFID = htonl(_EgressVRFID);

    memcpy((void*) ((char*)data_ptr + filllevel*sizeof(Data)), (void*) &tmp_data, sizeof(Data));

    ++filllevel;
    currentPosition_ptr = (void*) ((char*) data_ptr + filllevel*sizeof(Data));

    return 1;
}

void
NetFlowBuilderv6::set_packageSequence(uint32_t new_value)
{
    if(!header_ptr) ;
    else {
        uint32_t tmp_new = htonl(new_value);
        memcpy((char*)header_ptr+2*sizeof(uint16_t)+2*sizeof(uint32_t), &tmp_new, sizeof(uint32_t));
    }
}

void
NetFlowBuilderv6::set_sysUptime(uint32_t new_value)
{
    if(!header_ptr) ;
    else {
        uint32_t tmp_new = htonl(new_value);
        memcpy((char*)header_ptr+2*sizeof(uint16_t), &tmp_new, sizeof(uint32_t));
    }
}

void
NetFlowBuilderv6::set_unixSeconds(uint32_t new_value)
{
    if(!header_ptr) ;
    else {
        uint32_t tmp_new = htonl(new_value);
        memcpy((char*)header_ptr+2*sizeof(uint16_t)+1*sizeof(uint32_t), &tmp_new, sizeof(uint32_t));
    }
}

void
NetFlowBuilderv6::clear_filllevel()
{
    filllevel = 0;
}

/* --- GETTER METHODS ---*/

/* --- Returns 1 if full; else 0 --- */
int
NetFlowBuilderv6::is_full()
{
    if(capacity <= filllevel) return 1;
    else return 0;
}

uint16_t 
NetFlowBuilderv6::get_header_count()
{
    return capacity + 1; // capacity defines the number of data records + one template record
}

uint16_t
NetFlowBuilderv6::get_template_length()
{
    return sizeof(Template);
}

uint16_t
NetFlowBuilderv6::get_template_fieldCount()
{
    uint16_t nmbr_of_elements = sizeof(Template) / sizeof(uint16_t);
    uint16_t nmbr_without_static_fields = nmbr_of_elements - 4; // There are always 4 static fields
    uint16_t nmbr_of_fields = nmbr_without_static_fields / 2; // There is alaways a field type and a field length name per field
    return nmbr_of_fields;
}

uint16_t 
NetFlowBuilderv6::get_dataHeader_length()
{
    return (sizeof(DataHeader) + (capacity*sizeof(Data)));
}

uint32_t
NetFlowBuilderv6::get_packageSequence()
{
    if(!header_ptr) return 0;
    else {
        uint32_t tmp_packageSequence;
        tmp_packageSequence = ntohl(*(uint32_t*)((char*)header_ptr+2*sizeof(uint16_t)+2*sizeof(uint32_t)));
        return tmp_packageSequence;
    }
}

void*
NetFlowBuilderv6::get_packet() 
{
    return packet_ptr;
}

size_t
NetFlowBuilderv6::get_packet_size()
{
   return (sizeof(Header) + sizeof (Template) + sizeof (DataHeader) + (capacity*sizeof(Data)));
}

/* --- GENERAL METHODS --- */
size_t
NetFlowBuilderv6::calc_needed_memory()
{
    /*
    std::cout << "Header: " << sizeof(Header) << std::endl;
    std::cout << "Template: " << sizeof(Template) << std::endl;
    std::cout << "DataHeader: " << sizeof(DataHeader) << std::endl;
    std::cout << "Data: " << sizeof(Data) << std::endl;
    */

    return (sizeof(Header) + sizeof (Template) + sizeof (DataHeader) + (capacity*sizeof(Data)));
}

void
NetFlowBuilderv6::set_pointer()
{
    header_ptr = packet_ptr;
    template_ptr = (void*)((char*) header_ptr + sizeof(Header));
    dataHeader_ptr = (void*)((char*) template_ptr + sizeof(Template));
    data_ptr = (void*)((char*) dataHeader_ptr + sizeof(DataHeader));
    currentPosition_ptr = packet_ptr;
}
