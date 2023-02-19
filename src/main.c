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
		exit(2);
	}
	if((len / 2) > arr_cnt)
	{
		printf("Buffer too small, string is %d characters long, 2 characters per byte.", (int)len);
		exit(3);
	}
    /* WARNING: no sanitization or error-checking whatsoever */
    for (size_t count = 0; count < arr_cnt; count++) {
		if (*pos == '\0')
			break;
		if (sscanf(pos, "%2hhx", &arr[count]) <= 0)
		{
			printf("Invalid hexadecimal character: '%c' or '%c'", *pos, *(pos+1));
			exit(4);
		}
        pos += 2;
    }
	return;
}
int main(int argc, char* argv[])
{
	if (argc < 6)
		return 91;
	printf("Application started\n");
	uint8_t buf[LARGEST_ETHERNET_PACKET_SIZE];
	HexString2ByteArray(&buf[0], LARGEST_ETHERNET_PACKET_SIZE, argv[1]);
	Ipv4Info info;
	info.dscp = 99;
	info.optionsPresent = true;
	info.protocol = 99;
	bool res = ethIpv4Parse(&buf, sizeof(buf), &info);
	if (res != (bool)(atoi(argv[2])))
		return 92;
	
	if (info.dscp != atoi(argv[3]))
		return 93;
	
	if (info.optionsPresent != (bool)atoi(argv[4]))
		return 94;

	if (info.protocol != atoi(argv[5]))
		return 95;

	printf("Application closing\n");
	return 0;
}
