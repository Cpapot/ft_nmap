#include "../../inc/scan.h"

struct pseudo_header {
    uint32_t source_address;
    uint32_t dest_address;
    uint8_t placeholder;
    uint8_t protocol;
    uint16_t tcp_length;
};

uint16_t get_src_port_for_scan(int scan_type) {
    switch (scan_type) {
        case SYN:  return SRC_PORT_SYN;
        case NULLMODE:  return SRC_PORT_NULL;
        case ACK: return SRC_PORT_ACK;
        case FIN: return SRC_PORT_FIN;
        case XMAS: return SRC_PORT_XMAS;
        case UDP: return SRC_PORT_UDP;
        default:        return 33000 + scan_type;
    }
}

int get_local_ip(const char *dst_ip, char *buffer) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in serv;
    struct sockaddr_in name;
    socklen_t namelen = sizeof(name);

    if (sock < 0) return -1;
    memset(&serv, 0, sizeof(serv));
    serv.sin_family = AF_INET;
    serv.sin_addr.s_addr = inet_addr(dst_ip);
    serv.sin_port = htons(80);

    if (connect(sock, (const struct sockaddr *)&serv, sizeof(serv)) < 0) {
        close(sock);
        return -1;
    }
    
    if (getsockname(sock, (struct sockaddr *)&name, &namelen) < 0) {
        close(sock);
        return -1;
    }
    
    inet_ntop(AF_INET, &name.sin_addr, buffer, INET_ADDRSTRLEN);
    close(sock);
    return 0;
}

uint16_t checksum(void *b, int len) {
    uint16_t *buf = b;
    uint32_t sum = 0;
    uint16_t result;

    for (sum = 0; len > 1; len -= 2)
        sum += *buf++;
    if (len == 1)
        sum += *(uint8_t *)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

uint16_t tcp_checksum(struct iphdr *iph, struct tcphdr *tcph) {
    struct pseudo_header psh;
    char *pseudogram;
    int psize;
    uint16_t result;

    ft_bzero(&psh, sizeof(struct pseudo_header));

    // build pseudo header
    psh.source_address = iph->saddr;
    psh.dest_address = iph->daddr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(sizeof(struct tcphdr));

    // Concat pseudo-header + TCP header
    psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr);
    pseudogram = malloc(psize);
    memcpy(pseudogram, &psh, sizeof(struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header), tcph, sizeof(struct tcphdr));

    result = checksum(pseudogram, psize);
    free(pseudogram);
    return result;
}

int build_packet(char *datagram, char *dest_ip, uint16_t dest_port, int scan_type) {
    struct iphdr *iph = (struct iphdr *)datagram;
    struct tcphdr *tcph = (struct tcphdr *)(datagram + sizeof(struct iphdr));
    char my_ip[INET_ADDRSTRLEN];

    get_local_ip(dest_ip, my_ip);


    //=== IP HEADER ===
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
    iph->id = htons(rand() % 65535);
    iph->frag_off = 0;
    iph->ttl = 64;
    iph->protocol = IPPROTO_TCP;

    iph->daddr = inet_addr(dest_ip);
    iph->saddr = inet_addr(my_ip);

    iph->check = 0;
    iph->check = checksum(datagram, sizeof(struct iphdr));

    //=== TCP HEADER ===
    tcph->source = htons(get_src_port_for_scan(scan_type));
    tcph->dest = htons(dest_port);
    tcph->seq = htonl(rand());
    tcph->ack_seq = 0;
    tcph->doff = 5;
    tcph->window = htons(5840);
    tcph->urg_ptr = 0;

    tcph->fin = 0;
    tcph->syn = 0;
    tcph->rst = 0;
    tcph->psh = 0;
    tcph->ack = 0;
    tcph->urg = 0;

    // Flags according to scan type
    switch (scan_type) {
        case SYN:
            tcph->syn = 1;
            break;
        case NULLMODE:
            // all flags to 0
            break;
        case ACK:
            tcph->ack = 1;
            tcph->ack_seq = htonl(1);
            break;
        case FIN:
            tcph->fin = 1;
            break;
        case XMAS:
            tcph->fin = 1;
            tcph->psh = 1;
            tcph->urg = 1;
            break;
    }

    // Calcul du checksum TCP
    tcph->check = 0;
    tcph->check = tcp_checksum(iph, tcph);

    return sizeof(struct iphdr) + sizeof(struct tcphdr);
}

int send_tcp_packet(char *dest_ip, uint16_t dest_port, int scan_type) {
    int sockfd;
    char datagram[4096];
    struct sockaddr_in dest;
    int one = 1;

    // Socket raw TCP
    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sockfd < 0) {
        perror("socket");
        return -1;
    }

    if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        perror("setsockopt");
        close(sockfd);
        return -1;
    }

    int packet_size = build_packet(datagram, dest_ip, dest_port, scan_type);

    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = inet_addr(dest_ip);

    if (sendto(sockfd, datagram, packet_size, 0,
               (struct sockaddr *)&dest, sizeof(dest)) < 0) {
        perror("sendto");
        close(sockfd);
        return -1;
    }

    close(sockfd);
    return 0;
}


void packet_parsing(t_port_result *result, char * buffer) {
     struct iphdr *iph = (struct iphdr *)buffer;

     // ==== TCP ===
     if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = (struct tcphdr *)(buffer + iph->ihl * 4);
        uint16_t scanned_port = ntohs(tcph->source); 
        uint16_t src_port = ntohs(tcph->dest);
        int scan_type = src_port - 33000;
        int scan_index = scan_type -1;

        if (src_port < 33001 || src_port > 33006)
            return;

        result[scanned_port].scans[scan_index].answered = true;

        if (scan_type == SYN){
                if (tcph->syn && tcph->ack)
                   result[scanned_port].scans[scan_index].state = PORT_OPEN;
               else if (tcph->rst)
                   result[scanned_port].scans[scan_index].state = PORT_CLOSED;
        }
        else if (scan_type == ACK) {
            if (tcph->rst)
                   result[scanned_port].scans[scan_index].state = PORT_UNFILTERED;
        }
        else { // NULL, FIN, XMAS
            if (tcph->rst)
                   result[scanned_port].scans[scan_index].state = PORT_CLOSED;
        }
    }

    // ==== ICMP (UDP Error)
    else if (iph->protocol == IPPROTO_ICMP) {
        struct icmphdr *icmph = (struct icmphdr *)(buffer + (iph->ihl * 4));

        // 3: Dest Unreachable
        if (icmph->type == 3 && icmph->code == 3) {
            
            struct iphdr *orig_iph = (struct iphdr *)((char *)icmph + 8);
            struct udphdr *orig_udph = (struct udphdr *)((char *)orig_iph + (orig_iph->ihl * 4));

            uint16_t scanned_port = ntohs(orig_udph->dest);
            result[scanned_port].scans[UDP - 1].answered = 1;
            result[scanned_port].scans[UDP - 1].state = PORT_CLOSED;
        }
    }
}

int receiver(t_port_result *results) {
    int sock_tcp, sock_icmp;
    fd_set readfds;
    struct timeval timeout;
    char buffer[65536];

    sock_tcp = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    sock_icmp = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

    if (sock_tcp < 0 || sock_icmp < 0)
        return -1;
        
    while (1) {
        FD_ZERO(&readfds);
        FD_SET(sock_tcp, &readfds);
        FD_SET(sock_icmp, &readfds);

        timeout.tv_sec = 1;
        timeout.tv_usec = 0;
        int max_fd = (sock_tcp > sock_icmp ? sock_tcp : sock_icmp);
        if (select(max_fd,  &readfds, NULL, NULL, &timeout) < 0 )
            continue;

        if (FD_ISSET(sock_tcp, &readfds)) {
            if (recvfrom(sock_tcp, buffer, sizeof(buffer), 0, NULL, NULL) > 0)
                packet_parsing(results, buffer);
        }
        if (FD_ISSET(sock_icmp, &readfds)) {
          if (recvfrom(sock_icmp, buffer, sizeof(buffer), 0, NULL, NULL) > 0)
              packet_parsing(results, buffer);
        }
    }
    close(sock_tcp);
    close(sock_icmp);
}
