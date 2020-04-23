#include "pcapclient.h"
#include "net_headers.h"

#include <pcap/pcap.h>
#include <sys/socket.h>
#include <iostream>

#define UNUSED(x) ((void)(x))

static void
handle_packet(uint8_t* user, const struct pcap_pkthdr *hdr,
                const uint8_t* bytes)
{
    std::cout<<"Packet\n";
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