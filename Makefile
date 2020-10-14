all: send-arp

send-arp: main.c
		gcc -o send-arp main.c -l pcap

clean:
		rm send-arp