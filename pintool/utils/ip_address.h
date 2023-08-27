#pragma once

#include <stdint.h>
#include <ostream>

#include "sockaddr.h"

#include "enums.h"

// Helper functions for handling IPv4 addresses. For example:
// - Reading sockaddr_in
// - Formatting the address for pretty printing

struct Ipv4Address {
public:
	uint8_t b0;
	uint8_t b1;
	uint8_t b2;
	uint8_t b3;

    Ipv4Address();
    Ipv4Address(uint8_t b0, uint8_t b1, uint8_t b2, uint8_t b3);

    static Ipv4Address from_uint32(uint32_t val, ByteOrder byte_order);
    static Ipv4Address from_mem(uint8_t *mem, ByteOrder byte_order);

    uint32_t to_uint32(ByteOrder byte_order) const;
    
	friend std::ostream& operator<<(std::ostream& os, const Ipv4Address& addr);
};

struct Ipv4AddressPort {
public:
    Ipv4Address address;
    uint16_t port;
   
    Ipv4AddressPort();
    Ipv4AddressPort(uint8_t b0, uint8_t b1, uint8_t b2, uint8_t b3, uint16_t port);

    static Ipv4AddressPort from_sockaddr_in(const sockaddr_in *addr);

	friend std::ostream& operator<<(std::ostream& os, const Ipv4AddressPort& addr);
};