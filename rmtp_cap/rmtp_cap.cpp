#include <pcap.h>
#include "misc.h"
#include "types.h"
#include "tcp.h"
#include "capturer.h"
#include "parser.h"
/* prototype of the packet handler */
void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data);

int main()
{
	filter::PCAP_FILTER filter;
	pcap_if_t* alldevs;
	pcap_if_t* d;
	u_int netmask;
	int inum;
	int i = 0;
	char opts[20] = "tcp and udp";
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

	if (d->addresses != NULL)
		/* Retrieve the mask of the first address of the interface */
		netmask = ((struct sockaddr_in*)(d->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		/* If the interface is without addresses we suppose to be in a C class network */
		netmask = 0xffffff;

	filter.netmask = netmask;
	filter.filter_opts = (char*)opts;

	TCPCapturer* captureDevice = new TCPCapturer();
	
	captureDevice->SetDevice(*(pcap_if_t*)d);

	TCPParser* parser = new TCPParser();

	captureDevice->SetParser(parser);

	printf("\nlistening on %s...\n", d->description);

	/* At this point, we don't need any more the device list. Free it */
	pcap_freealldevs(alldevs);

	if (!captureDevice->BeginCapture(65536, PCAP_OPENFLAG_PROMISCUOUS, NULL, 1000, errbuf, TRUE, &filter))
	{
		//capture failed
		printf("[**] ERROR: %s\n", errbuf);
		return -1;
	}

	return 0;
}


/* Callback function invoked by libpcap for every incoming packet */
void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data)
{
	static int i = 0;
	types::TCP_PACKET packet;
	parse_tcp_packet(&packet ,pkt_data, header->len); 
	printf("Packet no. %d\n", i++);
	printf("packet src port %d\n", ntohs(packet.tcp_header.src_port));
	printf("packet dst port %d\n", packet.tcp_header.dest_port);
}

