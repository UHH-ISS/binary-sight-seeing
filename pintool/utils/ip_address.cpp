#include "ip_address.h"

Ipv4Address::Ipv4Address() {
    b0 = 0;
    b1 = 0;
    b2 = 0;
    b3 = 0;
}

Ipv4Address::Ipv4Address(uint8_t b0, uint8_t b1, uint8_t b2, uint8_t b3) {
    this->b0 = b0;
    this->b1 = b1;
    this->b2 = b2;
    this->b3 = b3;
}

Ipv4Address Ipv4Address::from_uint32(uint32_t val, ByteOrder byte_order) {
    Ipv4Address res;
    if (byte_order == ByteOrder::MSB_FIRST) {
        res.b0 = (val >> 24) & 0xff;
        res.b1 = (val >> 16) & 0xff;
        res.b2 = (val >>  8) & 0xff;
        res.b3 =  val        & 0xff;
    } else {
        res.b3 = (val >> 24) & 0xff;
        res.b2 = (val >> 16) & 0xff;
        res.b1 = (val >>  8) & 0xff;
        res.b0 =  val        & 0xff;
    }
    return res;
}

Ipv4Address Ipv4Address::from_mem(uint8_t *mem, ByteOrder byte_order) {
    Ipv4Address res;
    if (byte_order == ByteOrder::MSB_FIRST) {
        res.b0 = mem[0];
        res.b1 = mem[1];
        res.b2 = mem[2];
        res.b3 = mem[3];
    } else {
        res.b0 = mem[3];
        res.b1 = mem[2];
        res.b2 = mem[1];
        res.b3 = mem[0];
    }
    return res;
}

uint32_t Ipv4Address::to_uint32(ByteOrder byte_order) const {
    if (byte_order == ByteOrder::MSB_FIRST) {
        return
            b0 << 24 |
            b1 << 16 |
            b2 <<  8 |
            b3;
    } else {
        return
            b3 << 24 |
            b2 << 16 |
            b1 <<  8 |
            b0;
    }
}

std::ostream& operator<<(std::ostream& os, const Ipv4Address& addr) {
	os << unsigned(addr.b0) << '.'
		<< unsigned(addr.b1) << '.'
		<< unsigned(addr.b2) << '.'
		<< unsigned(addr.b3);
	return os;
}

Ipv4AddressPort::Ipv4AddressPort() {
    port = 0;
}

Ipv4AddressPort::Ipv4AddressPort(uint8_t b0, uint8_t b1, uint8_t b2, uint8_t b3, uint16_t port)
        : address(b0, b1, b2, b3) {
    this->port = port;
}

Ipv4AddressPort Ipv4AddressPort::from_sockaddr_in(const sockaddr_in *addr) {
    Ipv4AddressPort res;
    res.address = Ipv4Address::from_mem(&(((uint8_t *) addr)[4]), ByteOrder::MSB_FIRST);
    uint8_t *mem = (uint8_t *) addr;
    res.port = mem[2] << 8 | mem[3];
    return res;
}

std::ostream& operator<<(std::ostream& os, const Ipv4AddressPort& addr_port) {
	os << addr_port.address << ':' << unsigned(addr_port.port);
	return os;
}