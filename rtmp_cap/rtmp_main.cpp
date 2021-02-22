#include <pcap.h>
#include <vector>
#include "misc.h"
#include "types.h"
#include "tcp.h"
#include "rtmp_main.h"

network::PACKET_PAGE page;

void capure(pcap_t* adhandle, int packet_count)
{
	int res, i = 0;
	pcap_pkthdr* header;
	network::raw_packet* tmp;
	const u_char* pkt_data;

	while ((res = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0 && i < packet_count)
	{
		if (res == 0)
			/* Timeout elapsed */
			continue;
		tmp = new network::raw_packet;
		tmp->packet_raw = duplicate(pkt_data, header->len);
		tmp->packet_len = header->len;
		page.push_back(*tmp);
	}
}

int open_online(pcap_t* adhandle, pcap_if_t* d, pcap_if_t* alldevs, char* errbuf)
{
	bpf_program fcode;
	u_int netmask;
	int inum;
	int i = 0;
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
		printf("\n[**]Interface number out of range.\n");
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
		printf("\n[*]listening on %s...\n", d->description);
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
}

int main(int argc, char** argv)
{
	bpf_program fcode;
	pcap_t* adhandle;
	pcap_if_t* alldevs;
	pcap_if_t* d;
	u_int netmask = 0xffffff;
	int inum;
	int i = 0;
	char errbuf[PCAP_ERRBUF_SIZE];
	/* Load Npcap and its functions. */
	if (!LoadNpcapDlls())
	{
		fprintf(stderr, "Couldn't load Npcap\n");
		exit(1);
	}

	/* Open the capture file */
	if ((adhandle = pcap_open_offline("C:\\Users\\Admin\\Desktop\\C++ project\\rmtp\\Debug\\freebsd_rtmp_dump.pcap",			// name of the device
		errbuf					// error buffer
	)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the file \n[**] %s.\n", errbuf);
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
	int num_pkt = 10;
	int ret;
	capure(adhandle, PACKET_MAX_COUNT);
	std::vector<network::TCPStream*> s_arr;
	std::vector<network::TCPStream*>::iterator iter;
	network::TCPStreamAnalyzer* tsa = new network::TCPStreamAnalyzer;
	network::StreamManager* s_man = new network::StreamManager;
	tsa->set_mamager(s_man);
	s_arr = tsa->analyze(page);
	s_arr[0]->get_stream_info();
	/*
	while ((res = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0)
	{
		if (res == 0)

			continue;
		parse_tcp_packet(&parsed_packet, (u_char*)pkt_data, header->len);
		//payload check
		parsed_packet.packet_id = packet_count++;
		if (parsed_packet.payload != NULL)
		{
			//rmtp detection code
			printf("*****************\n");
			printf("packet no. %d\n", parsed_packet.packet_id);
			printf("%s:%d -> %s:%d\n", inet_ntoa(parsed_packet.p_ip_header->ip_src), ntohs(parsed_packet.p_tcp_header->th_sport),
				inet_ntoa(parsed_packet.p_ip_header->ip_src), ntohs(parsed_packet.p_tcp_header->th_dport));
			printf("seq: %u\n", parsed_packet.p_tcp_header->th_seq);
			printf("ack: %u\n", parsed_packet.p_tcp_header->th_ack);
		}
		else
		{
			//pass
		}
	}
	*/

	return 0;
}


