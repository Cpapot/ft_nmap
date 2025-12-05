#include "../../inc/scan.h"

struct pseudo_header {
    uint32_t source_address;
    uint32_t dest_address;
    uint8_t placeholder;
    uint8_t protocol;
    uint16_t tcp_length;
};

int get_local_ip(const char *dest_ip, char *output_ip) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0); 
    if (sock < 0) {
        perror("get_local_ip: socket failed");
        return -1;
    }

    struct sockaddr_in serv;
    memset(&serv, 0, sizeof(serv));
    serv.sin_family = AF_INET;
    serv.sin_addr.s_addr = inet_addr(dest_ip);
    serv.sin_port = htons(60000); 

    if (connect(sock, (const struct sockaddr *)&serv, sizeof(serv)) < 0) {
        perror("get_local_ip: connect failed"); 
        close(sock);
        return -1;
    }

    struct sockaddr_in name;
    socklen_t namelen = sizeof(name);

    if (getsockname(sock, (struct sockaddr *)&name, &namelen) < 0) {
        perror("get_local_ip: getsockname failed");
        close(sock);
        return -1;
    }

    close(sock);

    if (inet_ntop(AF_INET, &name.sin_addr, output_ip, INET_ADDRSTRLEN) == NULL) {
        perror("get_local_ip: inet_ntop failed");
        return -1;
    }

    return 0;
}

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
    printf("MY IP %s\n", my_ip);

    memset(datagram, 0, 4096);

    //=== IP HEADER ===
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
    iph->id = htons(rand() % 65535);
    iph->frag_off = 0;
    iph->ttl = 64;
    iph->protocol = IPPROTO_TCP;
    iph->saddr = inet_addr(my_ip);
    iph->daddr = inet_addr(dest_ip);
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

    const char *scan_names[] = {"", "SYN", "NULL", "ACK", "FIN", "XMAS", "UDP"};
    printf("%s packet sent to %s:%d\n", scan_names[scan_type], dest_ip, dest_port);

    close(sockfd);
    return 0;
}

int receiver() {
    int sockfd;
    fd_set readfds;
    struct timeval timeout;
    char buffer[65536];
    struct sockaddr_in saddr;
    int saddr_len = sizeof(saddr);
    ssize_t data_size;

    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sockfd < 0) {
        perror("socket");
        return -1;
    }
    
    while (1) {
        FD_ZERO(&readfds);
        FD_SET(sockfd, &readfds);

        timeout.tv_sec = 5;
        timeout.tv_usec = 0;

        int activity = select(sockfd + 1, &readfds, NULL, NULL, &timeout);
        if (activity < 0) {
            perror("select");
            close(sockfd);
            return -1;
        } else if (activity == 0) {
            printf("Timeout waiting for packets.\n");
            continue;
        }

        if (FD_ISSET(sockfd, &readfds)) {
            data_size = recvfrom(sockfd, buffer, sizeof(buffer), 0,
                                 (struct sockaddr *)&saddr, (socklen_t *)&saddr_len);
            if (data_size < 0) {
                perror("recvfrom");
                close(sockfd);
                return -1;
            }

            struct iphdr *iph = (struct iphdr *)buffer;
            struct tcphdr *tcph = (struct tcphdr *)(buffer + iph->ihl * 4);
            
            //Vérifier si c'est un de NOS ports source (33001-33006) ===
            uint16_t received_src_port = ntohs(tcph->dest);  // ton ancien src_port !
            if (received_src_port < 33001 || received_src_port > 33006) {
                continue;  // Ignorer les paquets qui ne nous concernent pas
            }
            
            // C'est un de NOS scans
            printf("Received OUR scan response from %s (src_port=%d): ", 
                   inet_ntoa(saddr.sin_addr), received_src_port);
            if (tcph->syn && tcph->ack) {
                printf("SYN-ACK\n");
            } else if (tcph->rst) {
                printf("RST\n");
            } else {
                printf("Other TCP flags (0x%x)\n", tcph->th_flags);
            }
        }
    }
}


int main(int argc, char *argv[]) {
    if (argc < 3) {
        printf("Usage: %s <dest_ip> <dest_port>\n", argv[0]);
        return 1;
    }

    if (getuid() != 0) {
        fprintf(stderr, "Error: Run as root!\n");
        return 1;
    }

    char *dst_ip = argv[1];
    uint16_t dst_port = atoi(argv[2]);

    printf("=== Testing all TCP scans ===\n\n");

    printf("SYN:\n");
    send_tcp_packet(dst_ip, dst_port, SYN);
    sleep(1);
    receiver();
    printf("NULL:\n");
    send_tcp_packet(dst_ip, dst_port, NULLMODE);
    sleep(1);
    receiver();
    printf("FIN:\n");
    send_tcp_packet(dst_ip, dst_port, FIN);
    receiver();
    sleep(1);
    printf("XMAS:\n");
    receiver();
    send_tcp_packet(dst_ip, dst_port, XMAS);
    sleep(1);
    receiver();
    printf("ACK:\n");
    send_tcp_packet(dst_ip, dst_port, ACK);
    receiver();

    return 0;
}