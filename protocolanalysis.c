#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <netinet/ip_icmp.h>
#include <time.h>

void packetHandler(unsigned char *userData, const struct pcap_pkthdr *pkthdr, const unsigned char *packet) {
    // Extract Ethernet header
    struct ethhdr *ethHeader = (struct ethhdr *)packet;

    // Print information about the captured packet
    printf("Capture Time: %s", ctime((const time_t *)&pkthdr->ts.tv_sec));
    printf("Packet captured! Length: %d bytes\n", pkthdr->len);

    // Identify the protocol type based on the Ethernet header
    if (ntohs(ethHeader->h_proto) == ETH_P_IP) {
        // Extract IP header
        struct iphdr *ipHeader = (struct iphdr *)(packet + sizeof(struct ethhdr));

        // Check if the packet contains a TCP header
        if (ipHeader->protocol == IPPROTO_TCP) {
            // Extract TCP header
            struct tcphdr *tcpHeader = (struct tcphdr *)(packet + sizeof(struct ethhdr) + sizeof(struct iphdr));

            printf("Ethernet Protocol: IPv4\n");
            printf("Source IP: %s\n", inet_ntoa(*(struct in_addr *)&(ipHeader->saddr)));
            printf("Destination IP: %s\n", inet_ntoa(*(struct in_addr *)&(ipHeader->daddr)));
            printf("Source Port: %d\n", ntohs(tcpHeader->source));
            printf("Destination Port: %d\n", ntohs(tcpHeader->dest));
            printf("Acknowledgement Number: %u\n", ntohl(tcpHeader->ack_seq));
            printf("TCP Protocol\n");
        } else if (ipHeader->protocol == IPPROTO_UDP) {
            // Extract UDP header
            struct udphdr *udpHeader = (struct udphdr *)(packet + sizeof(struct ethhdr) + sizeof(struct iphdr));

            printf("Ethernet Protocol: IPv4\n");
            printf("Source IP: %s\n", inet_ntoa(*(struct in_addr *)&(ipHeader->saddr)));
            printf("Destination IP: %s\n", inet_ntoa(*(struct in_addr *)&(ipHeader->daddr)));
            printf("Source Port: %d\n", ntohs(udpHeader->source));
            printf("Destination Port: %d\n", ntohs(udpHeader->dest));
            printf("UDP Protocol\n");
        } else if (ipHeader->protocol == IPPROTO_ICMP) {
            printf("Ethernet Protocol: IPv4\n");
            printf("Source IP: %s\n", inet_ntoa(*(struct in_addr *)&(ipHeader->saddr)));
            printf("Destination IP: %s\n", inet_ntoa(*(struct in_addr *)&(ipHeader->daddr)));
            printf("ICMP Protocol\n");
        } else {
            printf("Unknown IP Protocol\n");
        }
    } else if (ntohs(ethHeader->h_proto) == ETH_P_IPV6) {
        printf("Ethernet Protocol: IPv6\n");
    } else if (ntohs(ethHeader->h_proto) == ETH_P_ARP) {
        printf("Ethernet Protocol: ARP\n");
    } else {
        printf("Unknown Ethernet Protocol\n");
    }

    printf("\n");
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];

    // Open the first live network interface
    pcap_t *handle = pcap_create("enp0s3", errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Could not create handle: %s\n", errbuf);
        return 1;
    }

    // Set the snapshot length to BUFSIZ
    if (pcap_set_snaplen(handle, BUFSIZ) != 0) {
        fprintf(stderr, "Error setting snapshot length\n");
        pcap_close(handle);
        return 1;
    }

    // Activate the handle
    if (pcap_activate(handle) != 0) {
        fprintf(stderr, "Error activating handle: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        return 1;
    }

    // Set a callback function to handle each captured packet
    pcap_loop(handle, 0, packetHandler, NULL);

    // Close the capture handle when done
    pcap_close(handle);

    return 0;
}
