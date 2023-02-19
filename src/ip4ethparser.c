#include <ip4ethparser.h>
#include <assert.h>
#include <stdio.h>

// https://en.wikipedia.org/wiki/Ethernet_frame#Structure
// https://en.wikipedia.org/wiki/IEEE_802.1ad
// https://en.wikipedia.org/wiki/Internet_Protocol_version_4

#define ETHER_TYPE_IPV4				0x0800
#define ETHER_TYPE_8021Q			0x8100
#define ETHER_TYPE_8021QINQ			0x88A8

#define MIN_ETHERNET_PACKET_SIZE	0x40
#define MIN_IP4_HEADER_SIZE			0x14
#define MAC_SIZE					0x6
#define TAG_802_1Q_SIZE				0x4
#define ETHERTYPE_SIZE				0x2

static uint16_t ether_type_ipv4 = ETHER_TYPE_IPV4;
static uint16_t ether_type_8021q = ETHER_TYPE_8021Q;
static uint16_t ether_type_8021qinq = ETHER_TYPE_8021QINQ;

//! Check for little endianess
/*!
* source: https://stackoverflow.com/questions/4239993/determining-endianness-at-compile-time
* \return true when on little endian machine (x86)
*/
bool isLittleEndian()
{
	short int number = 0x1;
	char* numPtr = (char*)&number;
	return (numPtr[0] == 1);
}
//! Compare two bytes long numbers from network and memory
/**
* Compare if two, two bytes long numbers are equal, note that first is in network format (big-endian) 
* and second is in our format (little endian) 
* \param net pointer to buffer containing big endian number (network format)
* \param machine pointer to buffer containing little endian number
* \return Two if numers are the same
* */
bool twobytecompare(const uint8_t* net, const uint8_t* machine )
{
	return (*net == *(machine + 1)) && (*(net + 1) == *machine);
}
bool ethIpv4Parse (const void* buffer, size_t bufLen, Ipv4Info* info)
{
	// Code is correct only on little endian machines
	assert(isLittleEndian());
	// bufLen is probably statically defined, so just check it in debug
	assert(bufLen > MIN_ETHERNET_PACKET_SIZE);
	const uint8_t* curr_pos = buffer;
	curr_pos += MAC_SIZE; // MAC destination
	curr_pos += MAC_SIZE; // MAC source

	// There may be more than one Tag present, or there may be none
	while (twobytecompare(curr_pos, (uint8_t*)&ether_type_8021q) || twobytecompare(curr_pos, (uint8_t*)&ether_type_8021qinq))
	{
		curr_pos += TAG_802_1Q_SIZE;
		// Infinite loop?
		if (curr_pos > ((uint8_t*)buffer + bufLen))
		{
			fprintf(stderr, "Buffer overrun.");
			exit(1);
		}
	}
	// Now we must be at ethertype, we are only interested in IPv4
	if (twobytecompare(curr_pos, (uint8_t*) & ether_type_ipv4))
	{
		curr_pos += ETHERTYPE_SIZE;
		// Is it safe to read whole IPv4 header without options?
		if (curr_pos + MIN_IP4_HEADER_SIZE > ((uint8_t*)buffer + bufLen))
		{
			fprintf(stderr, "Buffer overrun.");
			exit(1);
		}
		info->protocol = ((*curr_pos & 0xF0) >> 4);
		info->optionsPresent = ((*curr_pos & 0x0F)*4) > MIN_IP4_HEADER_SIZE;
		++curr_pos;
		info->dscp = *curr_pos >> 2;
		return true;
	}

	return false;
}