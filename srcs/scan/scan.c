#include "../../inc/scan.h"

struct pseudo_header {
    uint32_t source_address;
    uint32_t dest_address;
    uint8_t placeholder;
    uint8_t protocol;
    uint16_t tcp_length;
};

// Calcul du checksum (identique à ping)
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
    iph->saddr = 0;
    iph->daddr = inet_addr(dest_ip);
    iph->check = 0;
    iph->check = checksum(datagram, sizeof(struct iphdr));

    //=== TCP HEADER ===
    // source port aléatoire entre 1024-65535
    //tcph->source = htons(1024 + (rand() % (65535 - 1024)));
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
    printf("NULL:\n");
    send_tcp_packet(dst_ip, dst_port, NULLMODE);
    sleep(1);
    printf("FIN:\n");
    send_tcp_packet(dst_ip, dst_port, FIN);
    sleep(1);
    printf("XMAS:\n");
    send_tcp_packet(dst_ip, dst_port, XMAS);
    sleep(1);
    printf("ACK:\n");
    send_tcp_packet(dst_ip, dst_port, ACK);

    return 0;
}