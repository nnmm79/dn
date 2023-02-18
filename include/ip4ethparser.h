#include <stdbool.h>
#include <stdint.h>
typedef struct Ipv4Info
{    
	uint8_t dscp;         /* IPv4 DSCP field value */    
	uint8_t protocol;     /* IPv4 protocol field value */    
	bool optionsPresent;  /* Are IPv4 options present in the packet? */
}Ipv4Info;

//! Ethernet packet contains IPv4 packet?
/*
* \param buffer Buffer to beginning of Layer2 ethernet packet
* \param bufLen Size of buffer
* \param info Will contain extracted information from IPv4 packet, or unchanged when there is not an IPv4 packet
* \return true for IPv4 packet, otherwise false
*/
bool ethIpv4Parse (const void* buffer, size_t bufLen, Ipv4Info* info);