/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   main.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: cpapot <cpapot@student.42lyon.fr >         +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/11/05 17:06:26 by coco              #+#    #+#             */
/*   Updated: 2025/12/05 15:17:19 by cpapot           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "nmap.h"
#include "nmap_threads.h"

int		parsing(int argc, char **argv, t_nmap_data *data);
int		fill_unique_tasks(t_nmap_data *data);
t_threads_tasks	*distribute_tasks(t_nmap_data *data);
int		launch_threads(t_threads_data *threadsData, t_nmap_data *data);
int		send_packet(char *dest_ip, uint16_t dest_port, int scan_type);
int		receiver(t_port_result *results);


void *sniffer_routine(void *arg) {
	t_port_result *ports_results = (t_port_result *)arg;
	receiver(ports_results);
	return NULL;
}


// Add scan status for unanswered packets
void finalize_scan_results(t_port_result *results, t_nmap_data *data) {
    for (int i = 0; i < data->portsCount; i++) {
        int port = data->ports[i];
        
        for (int type_idx = 0; type_idx < SCAN_COUNT; type_idx++) {
            if (data->scanType[type_idx] == 0) continue;

            if (results[port].scans[type_idx].answered == true) continue;

            int scan_enum = type_idx + 1;
            
            if (scan_enum == SYN || scan_enum == ACK) {
                results[port].scans[type_idx].state = PORT_FILTERED;
            }
            else { // UDP, NULL, FIN, XMAS
                results[port].scans[type_idx].state = PORT_OPEN_FILTERED;
            }
        }
    }
}

int	nmap_error(char *error, t_nmap_data *data, int doExit)
{
	printf("%s %s", ERROR_PRINT, error);
	stock_free(&data->allocatedData);
	if (doExit == 1)
		exit(1);
	else
		return 1;
}

char *get_scan_name(int index) {
    char *names[] = {"SYN", "NULL", "ACK", "FIN", "XMAS", "UDP"};
    if (index >= 0 && index < 6) return names[index];
    return "UNK";
}

char *get_state_name(e_port_status state) {
    switch (state) {
        case PORT_OPEN: return "\033[1;32mOPEN\033[0m"; // Vert
        case PORT_CLOSED: return "\033[1;31mCLOSED\033[0m"; // Rouge
        case PORT_FILTERED: return "\033[1;33mFILTERED\033[0m"; // Jaune
        case PORT_UNFILTERED: return "UNFILTERED";
        case PORT_OPEN_FILTERED: return "\033[1;33mOPEN|FILTERED\033[0m"; // Jaune
        default: return "UNKNOWN";
    }
}

void print_scan_report(t_port_result *results, t_nmap_data data) {
    struct servent *service;
    
    printf("\n%-10s %-20s %-50s\n", "PORT", "SERVICE", "RESULTS");
    printf("----------------------------------------------------------------------------------\n");

    for (int i = 0; i < data.portsCount; i++) {
        int port = data.ports[i];
        
        service = getservbyport(htons(port), NULL);
        
        printf("%-10d %-20s ", port, (service ? service->s_name : "unknown"));
        
        int first = 1;
        for (int j = 0; j < SCAN_COUNT; j++) {
            if (data.scanType[j]) {
                if (!first) printf(", ");
                printf("%s %s", get_scan_name(j), get_state_name(results[port].scans[j].state));
                first = 0;
            }
        }
        printf("\n");
    }
    printf("\n");
}

int	main(int argc, char **argv)
{
	t_nmap_data data;
	pthread_t sniffer_thread;
	t_port_result ports_results[65536];

	ft_bzero(&ports_results, sizeof(ports_results));
	ft_bzero(&data, sizeof(t_nmap_data));

	if (parsing(argc, argv, &data))
		return 1;

	fill_unique_tasks(&data);

	if (pthread_create(&sniffer_thread, NULL, sniffer_routine, ports_results) != 0)
		return (nmap_error("Thread error",  &data, 1));
	sleep(1);

	if (data.threadsCount > 1)
	{
		t_threads_data	threadData;
		threadData.distributedTasks = distribute_tasks(&data);
		launch_threads(&threadData, &data);
	}
	else
	{
		for (int i = 0; i != data.taskCount; i++)
		{
			send_packet(data.uniqueTaskList[i].ipToScan, data.uniqueTaskList[i].portToScan, data.uniqueTaskList[i].scanType);
			usleep(5000);
		}
	}

	// waiting for late answers
	sleep(10);

	pthread_cancel(sniffer_thread);
	pthread_join(sniffer_thread, NULL);

	finalize_scan_results(ports_results, &data);

	stock_free(&data.allocatedData);

	print_scan_report(ports_results, data);

	return 0;
}
