# Network Packet Analysis with libpcap

This repository contains C code snippets demonstrating network packet analysis using libpcap, a packet capture library.

## Prerequisites

Ensure you have installed the following dependencies:

- libpcap-dev

## File Structure

### File: packet_analysis_1.c
- **Functionality**: Detects potential security threats by monitoring incoming packets and identifying source IPs that exceed a threshold.
- **How it Works**: Captures TCP packets and counts occurrences from unique source IPs.
- **Usage**: Run `packet_analysis_1.c` and specify the network interface (e.g., "enp0s3") to monitor.

### File: packet_analysis_2.c
- **Functionality**: Measures and logs network bandwidth in bytes per second.
- **How it Works**: Captures TCP packets and calculates bandwidth based on packet size and elapsed time.
- **Usage**: Run `packet_analysis_2.c` and specify the network interface (e.g., "enp0s3"). Generates a `bandwidth.txt` log file.

### File: packet_analysis_3.c
- **Functionality**: Provides detailed packet information including protocol, IP addresses, ports, and protocol types.
- **How it Works**: Captures packets and identifies Ethernet protocol type, IPv4/IPv6, TCP/UDP/ICMP protocols.
- **Usage**: Run `packet_analysis_3.c` and specify the network interface (e.g., "enp0s3").

### File: packet_analysis_4.c
- **Functionality**: Tracks unique source IPs and packet counts, writing the information to an output file.
- **How it Works**: Captures TCP packets and records occurrences of unique source IPs.
- **Usage**: Run `packet_analysis_4.c` and specify the network interface (e.g., "enp0s3"). Generates an `output.txt` log file.

## How to Use

1. Compile each C file using gcc: `gcc -o output_filename source_filename.c -lpcap`.
2. Run the compiled executable with appropriate permissions and specify the network interface.
3. Check the console output or generated log files for analysis results.

For more details, refer to the individual code files and their respective functionalities.
