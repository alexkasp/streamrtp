#include "pcapclient.h"
#include "net_headers.h"

#include <netinet/in.h>
#include <arpa/inet.h>
#include <pcap/pcap.h>
#include <sys/socket.h>
#include <iostream>
#include <cstring>


#define UNUSED(x) ((void)(x))

std::list<PortData> portList;

static void
handle_packet(uint8_t* user, const struct pcap_pkthdr *hdr,
                const uint8_t* bytes)
{
    struct iphdr* ip_header = (struct iphdr*)(bytes + sizeof(struct ethhdr));
    struct sockaddr_in  source, dest;
    
    memset(&source, 0, sizeof(source));
    memset(&dest, 0, sizeof(dest));
    source.sin_addr.s_addr = ip_header->saddr;
    dest.sin_addr.s_addr = ip_header->daddr;
        
    char source_ip[128];
    char dest_ip[128];
    strncpy(source_ip, inet_ntoa(source.sin_addr), sizeof(source_ip));
    strncpy(dest_ip, inet_ntoa(dest.sin_addr), sizeof(dest_ip));   
    
    int source_port = 0;
    int dest_port = 0;
    int data_size = 0;
    int ip_header_size = ip_header->ihl * 4;
    char* next_header = (char*)ip_header + ip_header_size;
                      
    if(ip_header->protocol == IP_HEADER_PROTOCOL_TCP)
     {
          struct tcphdr* tcp_header = (struct tcphdr*)next_header;
          source_port = ntohs(tcp_header->source);
          dest_port = ntohs(tcp_header->dest);
          int tcp_header_size = tcp_header->doff * 4;
          data_size = hdr->len - sizeof(struct ethhdr) -
          ip_header_size - tcp_header_size;
     }
     else if(ip_header->protocol == IP_HEADER_PROTOCOL_UDP)
     {
          struct udphdr* udp_header = (struct udphdr*)next_header;
          source_port = ntohs(udp_header->source);
          dest_port = ntohs(udp_header->dest);
          data_size = hdr->len - sizeof(struct ethhdr) -
          ip_header_size - sizeof(struct udphdr);
     }

     for(auto x = portList.begin();x!=portList.end();++x)
     {

        if((*x).port == dest_port)
        {
            printf("\n%s:%d -> %s:%d, %d (0x%x) bytes\n\n",
            source_ip, source_port, dest_ip, dest_port,
            data_size, data_size);
        }
    }
}


int PcapClient::startListen()
{
    int res;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live("eth0", 65535, 1, 100, errbuf);

    if(pcap == NULL)
    {
        fprintf(stderr, "pcap_open_live failed: %s\n", errbuf);
        return 1;
    }

    res = pcap_loop(pcap, -1, handle_packet, NULL);
        printf("pcap_loop returned %d\n", res);

        pcap_close(pcap);
        return 0;
}

int PcapClient::addPort(PortData pd)
{
    portList.push_back(pd);
}

int PcapClient::delPort(int port)
{
   portList.remove_if([port](PortData pd){return pd.port == port;});
}