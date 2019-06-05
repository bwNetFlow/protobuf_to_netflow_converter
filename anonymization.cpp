#include <iostream>
#include <string.h>
#include <cstddef>
#include <openssl/hmac.h>
#include "anonymization.hpp"

int
make_flow_anonymous_v4(kafka_input& kafka_values)
{
    unsigned char* digest;
    std::string key = "012345678";

    /* --- Hashing Src Addr --- */
    digest = HMAC(EVP_sha224(), (const unsigned char*) key.c_str(), key.size(),
        (const unsigned char*) kafka_values.IP4SrcAddr.c_str(), kafka_values.IP4SrcAddr.size(), NULL, NULL);

    memcpy((void*) &kafka_values.IP4SrcAddr[0], (void*) digest, kafka_values.IP4SrcAddr.size());

    /* --- Hashing Dst Addr --- */
    digest = HMAC(EVP_sha224(), (const unsigned char*) key.c_str(), key.size(),
        (const unsigned char*) kafka_values.IP4DstAddr.c_str(), kafka_values.IP4DstAddr.size(), NULL, NULL);

    memcpy((void*) &kafka_values.IP4DstAddr[0], (void*) digest, kafka_values.IP4DstAddr.size());

    return 1;
}
