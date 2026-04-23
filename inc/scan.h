#ifndef SCAN
# define SCAN
#include "nmap.h"
#include "network.h"

#define SRC_PORT_SYN    33001
#define SRC_PORT_NULL   33002
#define SRC_PORT_ACK    33003
#define SRC_PORT_FIN    33004  
#define SRC_PORT_XMAS   33005
#define SRC_PORT_UDP    33006

int             receiver(t_ip_result *ip_results, int ip_count);
void            packet_parsing(t_ip_result *ip_results, int ip_count, char *buffer);

#endif