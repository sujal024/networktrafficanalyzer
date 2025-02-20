#include <iostream>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <csignal>
#include <ctime>
#include <ncurses.h>
#include <vector>
#include <deque>
#include <cstring>
#include <chrono>
#include <stdexcept>
#include <algorithm>

volatile sig_atomic_t stop = 0;
pcap_t* global_handle = nullptr;

struct Stats {
    unsigned long tcp = 0;
    unsigned long udp = 0;
    unsigned long total_bytes = 0;
    unsigned long prev_tcp = 0;
    unsigned long prev_udp = 0;
    std::deque<unsigned long> tcp_history;
    std::deque<unsigned long> udp_history;
    std::chrono::steady_clock::time_point last_update;
    int link_type = DLT_EN10MB;
};

Stats stats;
const int history_size = 25;
const int graph_width = 50;

void sig_handler(int sig) {
    if (global_handle) pcap_breakloop(global_handle);
    stop = 1;
    endwin();
}

void update_display() {
    clear();
    mvprintw(0, 0, "=== Real-time Network Analysis ===");
    mvprintw(2, 0, "TCP: %lu", stats.tcp);
    mvprintw(3, 0, "UDP: %lu", stats.udp);

    // Bandwidth calculation
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        now - stats.last_update).count();
    double seconds = elapsed / 1000.0;
    unsigned long kb_ps = (stats.total_bytes / 1024) / (seconds > 0 ? seconds : 1);
    mvprintw(4, 0, "Bandwidth: %lu KB/s", kb_ps);

    // Update history with deltas
    unsigned long tcp_delta = stats.tcp - stats.prev_tcp;
    unsigned long udp_delta = stats.udp - stats.prev_udp;
    stats.prev_tcp = stats.tcp;
    stats.prev_udp = stats.udp;

    if (stats.tcp_history.size() >= history_size) stats.tcp_history.pop_front();
    if (stats.udp_history.size() >= history_size) stats.udp_history.pop_front();
    stats.tcp_history.push_back(tcp_delta);
    stats.udp_history.push_back(udp_delta);

    // Calculate max values with minimum of 1
    unsigned long max_tcp = 1, max_udp = 1;
    if (!stats.tcp_history.empty()) {
        max_tcp = *std::max_element(stats.tcp_history.begin(), stats.tcp_history.end());
        max_tcp = std::max(max_tcp, 1UL);
    }
    if (!stats.udp_history.empty()) {
        max_udp = *std::max_element(stats.udp_history.begin(), stats.udp_history.end());
        max_udp = std::max(max_udp, 1UL);
    }

    // Draw dynamic graphs
    mvprintw(6, 0, "Traffic Graph (last %d samples):", history_size);
    for (int i = 0; i < history_size; ++i) {
        int tcp_val = 0, udp_val = 0;
        if (i < stats.tcp_history.size()) {
            tcp_val = (stats.tcp_history[i] * graph_width) / max_tcp;
            tcp_val = std::clamp(tcp_val, 0, graph_width);
        }
        if (i < stats.udp_history.size()) {
            udp_val = (stats.udp_history[i] * graph_width) / max_udp;
            udp_val = std::clamp(udp_val, 0, graph_width);
        }

        mvprintw(8 + i, 0, "TCP: ");
        for (int j = 0; j < tcp_val; ++j) mvaddch(8 + i, 6 + j, '#');

        mvprintw(8 + i, 60, "UDP: ");
        for (int j = 0; j < udp_val; ++j) mvaddch(8 + i, 66 + j, '*');
    }
    refresh();
}

void packet_handler(u_char* user, const pcap_pkthdr* hdr, const u_char* packet) {
    Stats* stats = reinterpret_cast<Stats*>(user);
    stats->total_bytes += hdr->len;

    int link_offset = 0;
    switch (stats->link_type) {
        case DLT_EN10MB:    link_offset = sizeof(ether_header); break;
        case DLT_LINUX_SLL: link_offset = 16; break;
        default: return;
    }

    if (hdr->caplen < link_offset + sizeof(ip)) return;

    const ip* iph = reinterpret_cast<const ip*>(packet + link_offset);
    if (iph->ip_v != 4 || iph->ip_hl < 5) return;

    uint16_t ip_len = ntohs(iph->ip_len);
    if (hdr->caplen < link_offset + ip_len) return;

    switch (iph->ip_p) {
        case IPPROTO_TCP:
            if (ip_len >= sizeof(tcphdr)) stats->tcp++;
            break;
        case IPPROTO_UDP:
            if (ip_len >= sizeof(udphdr)) stats->udp++;
            break;
    }
}

int main() {
    struct sigaction sa;
    sa.sa_handler = sig_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    sigaction(SIGINT, &sa, nullptr);

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* devices;

    if (pcap_findalldevs(&devices, errbuf) == -1) {
        std::cerr << "Error finding devices: " << errbuf << std::endl;
        return 1;
    }

    int index = 0;
    std::vector<pcap_if_t*> valid_devices;
    for (pcap_if_t* d = devices; d; d = d->next) {
        std::cout << ++index << ". " << d->name;
        std::string status = " [INACTIVE]";
        if ((d->flags & PCAP_IF_UP) && (d->flags & PCAP_IF_RUNNING)) {
            status = " [ACTIVE]";
        }
        std::cout << status;
        
        if (strstr(d->name, "lo")) std::cout << " (Loopback)";
        else if (strstr(d->name, "w")) std::cout << " (Wireless)";
        else if (strstr(d->name, "eth")) std::cout << " (Ethernet)";
        std::cout << std::endl;
        
        valid_devices.push_back(d);
    }

    if (valid_devices.empty()) {
        std::cerr << "No available interfaces!" << std::endl;
        return 1;
    }

    std::cout << "Select interface (1-" << valid_devices.size() << "): ";
    std::cin >> index;
    if (index < 1 || index > valid_devices.size()) {
        std::cerr << "Invalid selection!" << std::endl;
        pcap_freealldevs(devices);
        return 1;
    }

    pcap_if_t* dev = valid_devices[index - 1];
    if (!(dev->flags & PCAP_IF_UP) || !(dev->flags & PCAP_IF_RUNNING)) {
        std::cerr << "Error: Selected interface is inactive!" << std::endl;
        pcap_freealldevs(devices);
        return 1;
    }

    global_handle = pcap_open_live(dev->name, BUFSIZ, 1, 1000, errbuf);
    if (!global_handle) {
        std::cerr << "Error opening interface: " << errbuf << std::endl;
        pcap_freealldevs(devices);
        return 1;
    }

    stats.link_type = pcap_datalink(global_handle);
    if (stats.link_type != DLT_EN10MB && stats.link_type != DLT_LINUX_SLL) {
        std::cerr << "Unsupported link type: " << stats.link_type << std::endl;
        pcap_close(global_handle);
        pcap_freealldevs(devices);
        return 1;
    }

    initscr();
    cbreak();
    noecho();
    curs_set(0);
    timeout(0);
    stats.last_update = std::chrono::steady_clock::now();

    while (!stop) {
        int result = pcap_dispatch(global_handle, 10, packet_handler, 
                                 reinterpret_cast<u_char*>(&stats));
        if (result < 0) break;

        auto now = std::chrono::steady_clock::now();
        if (std::chrono::duration_cast<std::chrono::seconds>(now - stats.last_update).count() >= 1) {
            update_display();
            stats.total_bytes = 0;
            stats.last_update = now;
        }
        napms(100);
    }

    pcap_close(global_handle);
    pcap_freealldevs(devices);
    endwin();
    return 0;
}
