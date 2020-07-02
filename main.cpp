/*
 Copyright (c) 2012, Tom Steele & Jeremi Gosney
 all rights reserved.
 
 Redistribution and use in source and binary forms, with or without
 modification, are permitted provided that the following conditions are met: 
 
 1. Redistributions of source code must retain the above copyright notice, this
 list of conditions and the following disclaimer. 
 2. Redistributions in binary form must reproduce the above copyright notice,
 this list of conditions and the following disclaimer in the documentation
 and/or other materials provided with the distribution. 
 
 THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
 ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 
 mook, a tool for discovery available ports through a filtering device
 that uses some form of SYN Flood protections.
 
 Author: Tom Steele tom@huptwo34.com
 Contributers: Jeremi Gosney epixoip@bindshell.nl
 Site: http://www.huptwo34.com
 Dependencies: libpcap-dev 

*/

#include <iostream>
#include <algorithm>
#include <functional>
#include <vector>
#include <string>
#include <string.h>
#include <iomanip>
#include <stdlib.h>
#include <getopt.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <fcntl.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#define __FAVOR_BSD
#include <netinet/tcp.h>
#include <pcap.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include "ports.h"
#include "iface.h"

#define TH_ACK 0x10
#define TH_FINACK 0x11
#define TH_PSHACK 0x18

void usage(void)
{
    std::cout << "Usage: mook [options] target\n"; 
    std::cout << "Options:\n";
    std::cout << "    -h               \t Show usage and exit.\n";
    std::cout << "    -i (interface)   \t Specify interface.\n";
    std::cout << "    -m (MSS Size)    \t Perform a mss option scan, specify option size\n";
    std::cout << "                     \t for open port.\n";
    std::cout << "    -n               \t Do not perform default connect scan.\n";
    std::cout << "    -p (port-string) \t Ports to scan ie: 80, 1-1000 or 80,443,8080.\n";
    std::cout << "                     \t Default: 1-1024.\n";
    std::cout << "    -t (milliseconds)\t Timeout in milliseconds to wait for connection.\n";
    std::cout << "                     \t Use a tool like nping to determine, Default: 500 ms.\n";
    std::cout << "                     \t If you use the default, you're gonna have a bad time.\n";
    std::cout << "    -s (milliseconds)\t Time to sleep in milliseconds between connections.\n";
    std::cout << "                     \t This is useful for evading things like tarpits.\n";
    std::cout << "    -c (number)      \t Confidence level for open ports.Default: 0.\n"; 
    std::cout << "    -r               \t Show reason for ports being open.\n";
    exit(1);
}

// global for connectScan to operate on
struct port_info {
    int port_number;
    int confidence_level;
    std::string reason;
};

// global temp variables
port_info temp_port_info;
int temp_mss_amount= 0;

// prototypes
void errorExit(std::string some_error);
const char* resolveHostname(const char *host);
void printHeader();
void printFooter();
void printResultHeader(const char *target, bool print_reason);
void printResults(std::vector<port_info> results, int confidence, bool print_reason);
void adjustPortInfo(int port, std::string reason);
void connectCallback(u_char *udata, const struct pcap_pkthdr *pkthdr, const u_char *packet);
void connectScan(const char *dev, const char *target, int port, int timeout);
int msScan(const char *dev, const char *source_ip, const char *target,
           int port, int timeout, int open_mss_amount);
void sendSyn(int sock, const char *target, const char *source_address, int port);
void mssCallback(u_char *udata, const struct pcap_pkthdr *pkthdr, const u_char *packet);

// function used when sorting a vector<int> of ports
bool sortPorts(const port_info &first, const port_info &second)
{
    return first.port_number < second.port_number;
}

//
// MAIN
//

int main(int argc, char * argv[])
{
    int timeout = 500000;
    int optional_mss_value = 0;
    int minimum_confidence = 1;
    int sleep_time = 0;
    bool do_connect_scan = true;
    bool show_reason = false;
    std::string optional_interface;
    std::string ports_string = "1-1024";
    
    // process command line options
    int c = 0;
    while ((c = getopt(argc, argv, "hi:m:np:t:s:c:r")) != -1)
        switch (c) {
            case 'h':
                usage();
                break;
            case 'i':
                optional_interface = optarg;
                break;
            case 'm':
                optional_mss_value = atoi(optarg);
                break;
            case 'n':
                do_connect_scan = false;
                break;
            case 'p':
                ports_string = optarg;
                break;
            case 't':
                // we take in ms and turn it into microseconds
                timeout = atoi(optarg) * 1000;
                // set timeout above 1600000 and things start to freak out
                // i have yet to determine the exact reason
                if (timeout > 1600000)
                    errorExit("Timeout set to high!");
                break;
            case 's':
                sleep_time = atoi(optarg) * 1000;
                break;
            case 'c':
                minimum_confidence = atoi(optarg);
                break;
            case 'r':
                show_reason = true;
                break;
            case '?':
                usage();
            default:
                abort();
        }
    
    uid_t uid = getuid(), euid=geteuid();
    if (uid > 0 || euid > 0)
        errorExit("mook must be run as root!");

    // check if target was given, and if we can resolve an ipaddress
    if (optind >= argc)
        errorExit("No target specified!");
    const char *target = resolveHostname(argv[optind]);
    
    // get the ip address of the interface specified on the command line
    // or get the first interface that we can sniff on
    iface source_details = getIface(optional_interface);
    
    // get a list of ports to scan from ports_string
    // note: explodePorts shuffles and uniques the vector
    std::vector<int> ports_to_scan(0);
    ports_to_scan = explodePorts(ports_string);
    
    std::vector<port_info> scan_results(0);
    
    printHeader();
 
    // here is where we actually start scanning ports
    int counter = 0;
    for(std::vector<int>::iterator port = ports_to_scan.begin();
        port != ports_to_scan.end();
        port++)
    {
        // print a pretty percentage so yall can know where the scan is at
        // bigups to totoro for showing me this
        if ((counter % 5) == 0) {
            std::cout << std::flush;
            std::cout << "\rScan at %" << (counter * 100 / ports_to_scan.size());
        }
        
        // do mss option scan
        if (optional_mss_value != 0) {
            int mss_result = msScan(source_details.name.c_str(),
                                    source_details.ip.c_str(), target,
                                    *port, timeout,
                                    optional_mss_value);
            if (mss_result == 1) 
                adjustPortInfo(*port, "MSS");
            
            temp_mss_amount = 0;
        }
        
        // connect scan
        if (do_connect_scan)
            connectScan(source_details.name.c_str(), target, *port, timeout);
        
        if (temp_port_info.port_number != 0)
            scan_results.push_back(temp_port_info);
        
        // reset temp_port_info
        temp_port_info.port_number = 0;
        temp_port_info.confidence_level = 0;
        temp_port_info.reason.clear();
        
        counter++;
        usleep(sleep_time);
    }
    
    std::cout << std::flush;
    std::cout << "\rScan complete\n";
    
    // sort connect_scan_info
    std::sort(scan_results.begin(), scan_results.end(), sortPorts);
    
    printResultHeader(target, show_reason);
    printResults(scan_results, minimum_confidence, show_reason);
    printFooter();
    
    return 0;
}

// generic function that simple prints an error message and exits
void errorExit(std::string some_error)
{
    std::cerr << some_error << std::endl;
    exit(1);
}

// attempts to resolve a suspect hostname and returns the ipaddress
const char *resolveHostname(const char *suspect_name)
{    
    struct hostent *host;
    if((host = gethostbyname(suspect_name)) == NULL) 
        errorExit("Unable to resolve target ip!");
    return inet_ntoa(*(struct in_addr*)(host->h_addr_list[0]));
}

// edits temp_port_info with details from a captured packet
void adjustPortInfo(int port, std::string reason)
{
    // adjust port number
    if (temp_port_info.port_number == 0)
        temp_port_info.port_number = port;
    
    // increase confidence by 1
    temp_port_info.confidence_level++;
    
    // adjust reason string
    if (temp_port_info.reason.empty()) {
        temp_port_info.reason = reason;
    } else {
        temp_port_info.reason += "," + reason;
    }
}

//
// CONNECT SCAN FUNCTIONS
//

void connectScan(const char* dev, const char *target, int port, int timeout)
{
    int res, sock = 0;
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = timeout;
    struct sockaddr_in addr;
    fd_set sockfd;
    
    // pcap variables
    pcap_t *pd;
    bpf_u_int32 netp, maskp;
    char filter[102];
    struct bpf_program fprog;
    char errbuff[PCAP_ERRBUF_SIZE];
    
    //filter for ACK, PSH/ACK, and FIN/ACK
    snprintf(filter, 102, "src %s and ((tcp[13] == 0x11) or (tcp[13] == 0x10) or (tcp[13] == 0x18)) and port %d",target, port);
    
    if ((pd = pcap_open_live(dev, 320, 0, ((timeout/1000) * 1.5), errbuff)) == NULL) {
        std::cerr << "\nCannont open interface " << errbuff << std::endl;
        exit(1);
    }
    pcap_lookupnet(dev, &netp, &maskp, errbuff);
    pcap_compile(pd, &fprog, filter, 0, netp);
    pcap_setfilter(pd, &fprog);
    pcap_freecode(&fprog);
    // connect socket non io blocking
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
        perror("socket");
    
    long arg = fcntl(sock, F_GETFL, NULL);
    arg |= O_NONBLOCK;
    fcntl(sock, F_SETFL, arg);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(target);
    if ((res = connect(sock, (struct sockaddr *)&addr, sizeof(addr))) < 0)
    {
        if (errno == EINPROGRESS)
        {
            FD_ZERO(&sockfd);
            FD_SET(sock, &sockfd);
            select(sock + 1, NULL, &sockfd, NULL, &tv);
        }
    }
    else
        perror("socket");
    
    close(sock);
    pcap_dispatch(pd, 3, &connectCallback, (u_char *) 14);
    pcap_close(pd);
}

// capture callback from connect scan
void connectCallback(u_char *udata, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
    struct tcphdr *tcp;
    tcp = (struct tcphdr *)(packet + (long)udata + sizeof(struct ip));
    
    std::string reason;
    if (tcp->th_flags == TH_ACK)
        reason = "ACK";
    else if (tcp->th_flags == TH_PSHACK)
        reason = "PSH/ACK";
    else if (tcp->th_flags == TH_FINACK)
        reason = "FIN/ACK";
    
    if (!reason.empty())
        adjustPortInfo(htons(tcp->th_sport), reason);  

}

//
// MSS SCAN FUNCTIONS
//


struct tcp_option_mss {
    uint8_t kind;
    uint8_t len;
    uint16_t mss;
} __attribute__((packed));

struct tcphdr_mss {
    struct tcphdr tcp_header;
    struct tcp_option_mss mss;
};

struct pseudoheader
{
    struct in_addr src;
    struct in_addr dst;
    unsigned char pad;
    unsigned char proto;
    unsigned short tcp_len;
    struct tcphdr tcp;
};

unsigned short in_cksum(unsigned short *addr, int len)
{
    int nleft = len;
    int sum = 0;
    unsigned short *w = addr;
    unsigned short answer = 0;
    
    while (nleft > 1)
    {
        sum += *w++;
        nleft -= 2;
    }
    
    if (nleft == 1)
    {
        *(unsigned char *) (&answer) = *(unsigned char *) w;
        sum += answer;
    }
    
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    
    return ~sum; 
}

unsigned short in_cksum_tcp(int src, int dst, unsigned short *addr, int len)
{
    struct pseudoheader buf;
    
    memset(&buf, 0, sizeof(struct pseudoheader));
    
    buf.src.s_addr = src;
    buf.dst.s_addr = dst;
    buf.pad = 0;
    buf.proto = IPPROTO_TCP;
    buf.tcp_len = htons(len);
    
    memcpy(&(buf.tcp), addr, len);
    
    return in_cksum((unsigned short *)&buf, 12 + len);
}

void sendSyn(int sock, const char *target, const char *source_address, int port)
{
    u_char *packet;
    
    struct ip ip;
    struct tcphdr tcp;
    struct sockaddr_in sin;
    
    packet = (u_char *)malloc(sizeof(struct ip) + sizeof(struct tcphdr));
    
    ip.ip_hl = 0x5;
    ip.ip_v = 0x4;
    ip.ip_tos = 0x0;
    ip.ip_len = sizeof(struct ip) + sizeof(struct tcphdr);
    ip.ip_id = htonl(rand());
    ip.ip_off = 0x00;
    ip.ip_ttl = 64;
    ip.ip_p = IPPROTO_TCP;
    ip.ip_sum = 0x0;
    ip.ip_src.s_addr = inet_addr(source_address);
    ip.ip_dst.s_addr = inet_addr(target);
    ip.ip_sum = in_cksum((unsigned short *)&ip, sizeof(struct ip));
    
    memcpy(packet, &ip, sizeof(struct ip));
    
    tcp.th_sport = htons(rand());
    tcp.th_dport = htons(port);
    tcp.th_seq = htonl(rand());
    tcp.th_ack = htonl(rand());
    tcp.th_off = sizeof(struct tcphdr) / 4;
    tcp.th_flags = TH_SYN;
    tcp.th_win = htons(512);
    tcp.th_urp = 0x00;
    tcp.th_sum = 0;
    tcp.th_sum = in_cksum_tcp(ip.ip_src.s_addr, ip.ip_dst.s_addr, 
                              (unsigned short *)&tcp, sizeof(struct tcphdr));
    
    memcpy((packet + sizeof(struct ip)), &tcp, sizeof(struct tcphdr));
    memset(&sin, 0, sizeof(struct sockaddr_in));
    
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = ip.ip_dst.s_addr;
    
    if (sendto(sock, packet, sizeof(struct ip) + sizeof(struct tcphdr), 0, 
               (struct sockaddr *)&sin, sizeof(struct sockaddr)) < 0)
        perror("sendto");
    free(packet);
    
}

int msScan(const char *dev, const char *source_ip, const char *target,
           int port, int timeout, int open_mss_amount)
{
    pcap_t *pd;
    bpf_u_int32 netp;
    bpf_u_int32 maskp;
    
    int sock;
    char filter[100];
    const int on = 1;
    struct bpf_program fprog;
    char errbuf[PCAP_ERRBUF_SIZE];
    
    if ((sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0)        
        perror("raw socket");
    
    
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &on, sizeof(int)) < 0)
        perror("setsockopt");
    
    // looking for SYN/ACK
    snprintf(filter, 100, "src %s and (tcp[13] = 0x12) and (tcp[20] = 02) and port %d", target, port);
    
    if ((pd = pcap_open_live(dev, 320, 0, (timeout/1000), errbuf)) == NULL)
    {
        std::cerr <<  "cannot open device " << dev << errbuf << std::endl;
        exit(1);
    }
    
    pcap_lookupnet(dev, &netp, &maskp, errbuf);
    pcap_compile(pd, &fprog, filter, 0, netp);
    pcap_setfilter(pd, &fprog);
    pcap_freecode(&fprog);
    
    sendSyn(sock, target, source_ip, port);
    close(sock);
    pcap_dispatch(pd, 1, &mssCallback, (u_char *) 14);
    pcap_close(pd);
    
    if (temp_mss_amount == open_mss_amount) {
        return 1;
    }
    
    return 0;
}

void mssCallback(u_char *udata, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
    struct tcphdr_mss *tcp;
    tcp = (struct tcphdr_mss *)(packet + (unsigned long)udata + sizeof(struct ip));
    temp_mss_amount = htons(tcp->mss.mss);    
}

//
// PRINTING FUNCTIONS BELOW
//

// prints starting time information
void printHeader()
{
    time_t the_time = time(NULL);
    tm *ut= localtime(&the_time);
    std::cout << "Starting mook at " << ut->tm_hour << ":" << ut->tm_min; 
    std::cout << ":" << ut->tm_sec << std::endl;
    std::cout << std::endl;
}

void printResultHeader(const char *target, bool print_reason)
{
    std::cout << "Scan report for: " << target << std::endl;
    std::cout.setf(std::ios_base::left);
    std::cout << std::setw(10) << "PORT" << std::setw(10) << "STATE"; 
    std::cout << std::setw(12) << "CONFIDENCE";
    if (print_reason)
        std::cout << "REASON";
    std::cout << std::endl;
    
}

void printResults(std::vector<port_info> results, int confidence, bool print_reason)
{
    int counter = 0;
    for (std::vector<port_info>::iterator it = results.begin(); it != results.end(); ++it)
    {
        if (results[counter].confidence_level >= confidence) {
            std::cout << std::setw(10) << results[counter].port_number;
            std::cout << std::setw(10) << "open";
            std::cout << std::setw(12) << results[counter].confidence_level;
            if (print_reason)
                std::cout << results[counter].reason;
            std::cout << std::endl;
        }
        counter++;
    }
}

// prints when scan finished
void printFooter()
{
    time_t end_time = time(NULL);
    tm *et= localtime(&end_time);
    std::cout << std::endl;
    std::cout << "Scan finished at " << et->tm_hour << ":" << et->tm_min; 
    std::cout << ":" << et->tm_sec << std::endl;
}


