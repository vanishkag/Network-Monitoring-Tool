#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/if_ether.h>
#include <time.h>

// Global variables to store previous timestamp, total bytes, and file pointer
time_t prevTimestamp = 0;
unsigned long long totalBytes = 0;
FILE *file;  // Declare file pointer globally

void packetHandler(const struct pcap_pkthdr *pkthdr, const unsigned char *packet) {
    // Extract Ethernet header
    struct ethhdr *ethHeader = (struct ethhdr *)packet;

    // Check if the packet contains an IP header
    if (ntohs(ethHeader->h_proto) == ETH_P_IP) {
        // Extract IP header
        struct iphdr *ipHeader = (struct iphdr *)(packet + sizeof(struct ethhdr));

        // Check if the packet contains a TCP header
        if (ipHeader->protocol == IPPROTO_TCP) {
            // Extract TCP header
            struct tcphdr *tcpHeader = (struct tcphdr *)(packet + sizeof(struct ethhdr) + sizeof(struct iphdr));

            // Calculate elapsed time since the previous packet
            time_t currentTimestamp = pkthdr->ts.tv_sec;
            unsigned long long bytes = pkthdr->len;

            if (prevTimestamp != 0) {
                // Calculate bandwidth in bytes per second
                double bandwidth = (double)(bytes) / (currentTimestamp - prevTimestamp);

                // Display and write the bandwidth to the file
                printf("Bandwidth: %.2f bytes/s\n", bandwidth);
                fprintf(file, "Bandwidth: %.2f bytes/s\n", bandwidth);

                // Update total bytes
                totalBytes += bytes;
            }

            // Update previous timestamp
            prevTimestamp = currentTimestamp;
        }
    }
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

    // Open file for writing in binary mode
    file = fopen("bandwidth.txt", "w");

    if (file == NULL) {
        perror("Error opening file");
        return 1;
    }

    // Set a callback function to handle each captured packet
    pcap_loop(handle, 0, packetHandler, NULL);

    // Close the capture handle and file when done
    pcap_close(handle);
    fclose(file);

    // Display and write total bandwidth to the file
    printf("Total Bandwidth: %llu bytes\n", totalBytes);
    fprintf(file, "Total Bandwidth: %llu bytes\n", totalBytes);

    return 0;
}
