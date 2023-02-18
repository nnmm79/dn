typedef struct Ipv4Info
{    
	uint8_t dscp;         /* IPv4 DSCP field value */    
	uint8_t protocol;     /* IPv4 protocol field value */    
	bool optionsPresent;  /* Are IPv4 options present in the packet? */
}Ipv4Info;

bool ethIpv4Parse (const void* buffer, size_t bufLen, Ipv4Info* info);