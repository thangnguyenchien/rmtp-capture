#include "types.h"
#include "tcp.h"
#include "utils.h"
void network::proto_info(int proto_flag)
{
	switch (proto_flag)
	{
	case PROTO_RTMPT:
		printf("RTMP\n");
	default:
		break;
	}
}
void network::parse_tcp_packet(network::tcp_packet* packet_out, u_char* packet_raw, int packet_size)
{
	packet_out->payload_size = 0;
	packet_out->p_ether_header = (network::ethernet_header*)(packet_raw);
	//To skip datalink layer, advance the offset to 14 bytes
	packet_out->p_ip_header = (network::ip_header*)(packet_raw + ETHERNET_HEADER_SIZE);
	packet_out->ip_header_size = IP_HL(packet_out->p_ip_header) * 4;

	if (packet_out->ip_header_size < MINIMUM_IP_HEADER_SIZE /* 20 */)

	{
#ifdef _DEBUG
		printf("invalid ip header len %d\n", packet_out->ip_header_size);
#endif
		return;
	}

	packet_out->p_tcp_header = (network::tcp_header*)(packet_raw + ETHERNET_HEADER_SIZE + packet_out->ip_header_size);
	packet_out->tcp_header_size = TH_OFF(packet_out->p_tcp_header) * 4;

	if (packet_out->tcp_header_size < MINIMUM_TCP_HEADER_SIZE)
	{
#ifdef _DEBUG
		printf("invalid tcp header len %d\n", packet_out->tcp_header_size);
#endif
		return;
	}

	packet_out->payload_size = packet_size - (ETHERNET_HEADER_SIZE + packet_out->ip_header_size
		+ packet_out->tcp_header_size);

	packet_out->payload = packet_out->payload_size > 0 ? (u_char*)(packet_raw + ETHERNET_HEADER_SIZE + packet_out->ip_header_size
		+ packet_out->tcp_header_size) : NULL;

}

void network::free_page(PACKET_PAGE page)
{
	std::vector<network::raw_packet>::iterator i;
	for (i = page.begin(); i != page.end(); i++)
	{
		free((i)->packet_raw);
		delete &i;
	}
	page.clear();
}

network::StreamManager::StreamManager()
{
	this->stream_count = 0;
}

network::StreamManager::~StreamManager()
{
	this->stream_list.clear();
}

int network::StreamManager::get_stream_count()
{
	return this->stream_count;
}

void network::StreamManager::add_new_stream(network::TCPStream* stream)
{
	stream->stream_id = this->stream_count++;
	this->stream_list.push_back(stream);
}

network::TCPStream* network::StreamManager::get_stream_by_ip_pair(ULONG ul_ip_p1, ULONG ul_ip_p2)
{
	std::vector<network::TCPStream*>::iterator i;
	for (i = this->stream_list.begin(); i != this->stream_list.end(); i++)
	{
		if ((*i)->compare_ip_pair(ul_ip_p1, ul_ip_p2))
		{
			return *i;
		}
	}
	return NULL;
}

network::TCPStream::TCPStream()
{
	this->stream_id = -1;
	this->has_proto = PROTO_EMPTY;
	this->payload_size = 0;
	this->ip_pair = new network::stream_ip_pair;
}

network::TCPStream::~TCPStream()
{
	delete this->ip_pair;
}

void network::TCPStream::analyze_packet(network::tcp_packet* packet)
{
	if (ntohs(packet->p_tcp_header->th_sport) == RTMP_DEFAULT_TCP_PORT || ntohs(packet->p_tcp_header->th_sport) == RTMP_DEFAULT_TCP_PORT)
	{
		packet->packet_appli_flag = PROTO_RTMPT;
	}
	else
	{
		packet->packet_appli_flag = PROTO_EMPTY;
	}
}

void network::TCPStream::get_stream_info()
{
	std::vector<network::tcp_packet*>::iterator i;
	for (i = this->packet_list.begin(); i != this->packet_list.end(); i++)
	{
		this->analyze_packet(*i);
		this->has_proto |= (*i)->packet_appli_flag;
	}
	proto_info(this->has_proto);
}

void network::TCPStream::add_packet_to_stream(network::tcp_packet* pkt)
{
	if (this->packet_list.empty())
	{
		this->ip_pair->ip_p1 = pkt->p_ip_header->ip_src;
		this->ip_pair->ip_p2 = pkt->p_ip_header->ip_dst;
	}
	this->payload_size += pkt->payload_size;
	this->packet_list.push_back(pkt);
}

bool network::TCPStream::compare_ip_pair(ULONG ul_ip_p1, ULONG ul_ip_p2)
{
	if ((DECAP_IN_ADDR_ULONG(this->ip_pair->ip_p1) == ul_ip_p1 && DECAP_IN_ADDR_ULONG(this->ip_pair->ip_p2) == ul_ip_p2)
		|| (DECAP_IN_ADDR_ULONG(this->ip_pair->ip_p1) == ul_ip_p2 && DECAP_IN_ADDR_ULONG(this->ip_pair->ip_p2) == ul_ip_p1))
	{
		return TRUE;
	}
	return FALSE;
}

network::TCPStreamAnalyzer::TCPStreamAnalyzer()
{
	this->packet_count = 0;
}

network::TCPStreamAnalyzer::TCPStreamAnalyzer(network::StreamManager* manager)
{
	this->stream_man = manager;
	this->packet_count = 0;
}

network::TCPStreamAnalyzer::~TCPStreamAnalyzer()
{


}

void network::TCPStreamAnalyzer::page_to_tcp_packet_list(network::PACKET_PAGE tcp_page)
{
	int i;
	network::tcp_packet tmp_pkt;
	for (i = 0; i < tcp_page.size(); i++)
	{
		network::parse_tcp_packet(&tmp_pkt, tcp_page.at(i).packet_raw, tcp_page.at(i).packet_len);
		this->pkt_list.push_back(tmp_pkt);
	}
}

void network::TCPStreamAnalyzer::set_mamager(network::StreamManager* manager)
{
	this->stream_man = manager;
}

void network::TCPStreamAnalyzer::find_stream()
{
	int i;
	network::TCPStream* s;
	for (i = 0; i < this->pkt_list.size(); i++)
	{
		if ((s = this->stream_man->get_stream_by_ip_pair(DECAP_IN_ADDR_ULONG(this->pkt_list.at(i).p_ip_header->ip_dst),
			DECAP_IN_ADDR_ULONG(this->pkt_list.at(i).p_ip_header->ip_src))) != NULL)
		{
			s->add_packet_to_stream(&this->pkt_list.at(i));
		}
		else
		{
			s = new TCPStream;
			this->stream_man->add_new_stream(s);
			s->add_packet_to_stream(&this->pkt_list.at(i));
		}
	}
}

std::vector<network::TCPStream*> network::TCPStreamAnalyzer::analyze(network::PACKET_PAGE page)
{
	this->page_to_tcp_packet_list(page);
	this->find_stream();
	return this->stream_man->stream_list;
}
