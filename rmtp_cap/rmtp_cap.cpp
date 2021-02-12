#include <pcap.h>
#include "misc.h"
#include "types.h"
#include "tcp.h"
#define DEFAULT_HEAP_SIZE 512
int main()
{
	bpf_program fcode;
	pcap_t* adhandle;
	pcap_if_t* alldevs;
	pcap_if_t* d;
	u_int netmask;
	int inum;
	int i = 0;
	char errbuf[PCAP_ERRBUF_SIZE];
	/* Load Npcap and its functions. */
	if (!LoadNpcapDlls())
	{
		fprintf(stderr, "Couldn't load Npcap\n");
		exit(1);
	}

	/* Retrieve the device list on the local machine */
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

	/* Print the list */
	for (d = alldevs; d; d = d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}

	if (i == 0)
	{
		printf("\nNo interfaces found! Make sure Npcap is installed.\n");
		return -1;
	}

	printf("Enter the interface number (1-%d):", i);
	scanf_s("%d", &inum);

	if (inum < 1 || inum > i)
	{
		printf("\nInterface number out of range.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* Jump to the selected adapter */
	for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);

	//assume all device is class C network
	netmask = 0xffffff;

	if (d != NULL && (adhandle = pcap_open(d->name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf)) != NULL)
	{
		printf("\nlistening on %s...\n", d->description);
	}
	else
	{
		printf("[**]failed to open the device\n");
		return -1;
	}

	if (pcap_compile(adhandle, &fcode, "tcp and ip", 1, netmask) < 0)
	{
		printf("[**]wrong filter syntax\n");
		return -1;
	}

	if (pcap_setfilter(adhandle, &fcode) < 0)
	{
		printf("[**]failed to set the filter on current device\n");
		return -1;
	}


	/* At this point, we don't need any more the device list. Free it */
	pcap_freealldevs(alldevs);

	int res, k;
	tcp::MyTcpPacket parsed_packet;
	pcap_pkthdr* header;
	const u_char* pkt_data;
	u_char* payload_copy;
	/* Retrieve the packets */
	if ((payload_copy = (u_char*)malloc(DEFAULT_HEAP_SIZE)) == NULL)
	{
		printf("[**] failed to allocate memory\n");
		return -1;
	}
	while ((res = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0)
	{
		if (res == 0)
			/* Timeout elapsed */
			continue;
		parse_tcp_packet(&parsed_packet, pkt_data, header->len);
		if (parsed_packet.payload != NULL)
		{
			if (parsed_packet.payload_size > DEFAULT_HEAP_SIZE
				&& (payload_copy = (u_char*)realloc(payload_copy, parsed_packet.payload_size)) != NULL)
			{
				printf("[**] failed to realloc payload\n");
				return -1;
			}
			memcpy(payload_copy, parsed_packet.payload, parsed_packet.payload_size);
			printf("\n*******\n");
			for (k = 0; k < parsed_packet.payload_size; k++)
			{
				printf("0x%02x ", payload_copy[k]);
			}
			printf("\n#######\n");
		}
		else
		{
			//pass
		}
	}

	if (res == -1)
	{
		printf("Error reading the packets: %s\n", pcap_geterr(adhandle));
		return -1;
	}
	return 0;
}


