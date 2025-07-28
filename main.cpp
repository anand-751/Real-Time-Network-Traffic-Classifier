#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <iostream>
#include <unordered_map>
#include <chrono>
#include <cstring>
#include <string>

using namespace std;
using namespace std::chrono;

unordered_map<int, string> portAppMap = {
    {80, "Browsing"},
    {443, "Browsing / Streaming"},
    {1935, "Streaming (RTMP)"},
    {554, "Streaming (RTSP)"},
    {3478, "Video Call (STUN)"},
    {5004, "Video Call (RTP)"},
    {5060, "Video Call (SIP)"},
    {3074, "Gaming (Xbox Live)"},
    {27015, "Gaming (Steam)"},
    {53, "DNS"},
    {123, "NTP"},
    {20, "File Transfer (FTP)"},
    {21, "File Transfer (FTP)"},
    {22, "SSH"},
    {25, "Email (SMTP)"},
    {110, "Email (POP3)"},
    {143, "Email (IMAP)"},
    {1900, "Other (SSDP/UPnP)"}
};

string classifyPort(int port) {
    if (portAppMap.count(port)) return portAppMap[port];
    if (port >= 1024 && port <= 65535) return "Streaming"; // heuristic
    return "Other";
}

void packetHandler(u_char *userData, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    const struct ip *ipHeader;
    const struct tcphdr *tcpHeader;
    const struct udphdr *udpHeader;
    string appType = "Other";

    // Skip Ethernet header (assume Ethernet II)
    ipHeader = (struct ip *)(packet + 14);
    int ipHeaderLen = ipHeader->ip_hl * 4;
    if (ipHeader->ip_p == IPPROTO_TCP) {
        tcpHeader = (struct tcphdr *)(packet + 14 + ipHeaderLen);
        int sport = ntohs(tcpHeader->th_sport);
        int dport = ntohs(tcpHeader->th_dport);
        appType = classifyPort(sport);
        if (appType == "Other") appType = classifyPort(dport);
        cout << "[ " << appType << " ] Src Port: " << sport << ", Dst Port: " << dport << endl;
    } else if (ipHeader->ip_p == IPPROTO_UDP) {
        udpHeader = (struct udphdr *)(packet + 14 + ipHeaderLen);
        int sport = ntohs(udpHeader->uh_sport);
        int dport = ntohs(udpHeader->uh_dport);
        appType = classifyPort(sport);
        if (appType == "Other") appType = classifyPort(dport);
        cout << "[ " << appType << " ] Src Port: " << sport << ", Dst Port: " << dport << endl;
    } else {
        cout << "[ Non-TCP/UDP Protocol ]" << endl;
    }
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs, *device;

    // Find all devices
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        cerr << "pcap_findalldevs failed: " << errbuf << endl;
        return 1;
    }

    // Choose first available device (you can hardcode your own)
    device = alldevs;
    if (!device) {
        cerr << "No devices found." << endl;
        return 1;
    }

    cout << "Sniffing on interface: " << device->name << endl;

    // Open live capture
    pcap_t *handle = pcap_open_live(device->name, BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        cerr << "pcap_open_live failed: " << errbuf << endl;
        return 1;
    }

    // Only capture IP packets
    struct bpf_program fp;
    if (pcap_compile(handle, &fp, "ip", 0, PCAP_NETMASK_UNKNOWN) == -1 || pcap_setfilter(handle, &fp) == -1) {
        cerr << "Failed to set filter" << endl;
        return 1;
    }

    // Start packet capture loop
    pcap_loop(handle, 0, packetHandler, nullptr);

    // Cleanup
    pcap_freealldevs(alldevs);
    pcap_close(handle);
    return 0;
}
