#include "ip4ethparser.h"
#include <stdio.h>

#define LARGEST_ETHERNET_PACKET_SIZE 9000 // Jumbo frame MTU (size)

// Original code taken from https://stackoverflow.com/questions/3408706/hexadecimal-string-to-byte-array-in-c
// Function is useful for converting hexstream from wireshark to binary stream
void HexString2ByteArray(uint8_t* arr, size_t arr_cnt, const char* hexstring)
{
    const char* pos = hexstring;
	size_t len = strlen(hexstring);
	if (len % 2 != 0)
	{
		printf("Hexstream size must be divisible by 2, we get %d", (int)len);	// what is format specifier? ull does not seem to work?
		abort();
	}
    /* WARNING: no sanitization or error-checking whatsoever */
    for (size_t count = 0; count < arr_cnt; count++) {
		if (*pos == '\0')
			break;
		if (sscanf(pos, "%2hhx", &arr[count]) <= 0)
		{
			printf("Buffer too small, string is %d characters long, 2 characters per byte.", (int)len);
			exit(2);
		}
        pos += 2;
    }
	return;
}
int main()
{
	printf("Application started\n");
	uint8_t buf[LARGEST_ETHERNET_PACKET_SIZE];
	HexString2ByteArray(&buf[0], LARGEST_ETHERNET_PACKET_SIZE, "145afc168c4f1027f51c3eea0800450000286d2f400039062f22d1c50308c0a810090050f30a635f2af360d81808501100930f3400000000b2e01954");
	Ipv4Info info;
	bool res = ethIpv4Parse(&buf, sizeof(buf), &info);
	printf("Application closing\n");
	return 0;
}