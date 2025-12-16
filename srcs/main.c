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
int		send_tcp_packet(char *dest_ip, uint16_t dest_port, int scan_type);
int		receiver(t_port_result *results);


void *sniffer_routine(void *arg) {
	t_port_result *ports_results = (t_port_result *)arg;
	receiver(ports_results);
	return NULL;
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
			send_tcp_packet(data.uniqueTaskList[i].ipToScan, data.uniqueTaskList[i].portToScan, data.uniqueTaskList[i].scanType);
			usleep(1000);
		}
	}

	//later add retry here instead
	printf("Scan finished. Waiting for late packets\n");
	sleep(10);

	pthread_cancel(sniffer_thread);
	pthread_join(sniffer_thread, NULL);
	stock_free(&data.allocatedData);

	// test print
	// printf("\n%-10s %-10s %-15s\n", "PORT", "STATE", "SERVICE");
	
	// for (int port = 0; port < 65536; port++)
	// {
	//     if (ports_results[port].port != NULL)
	//     {
	//         printf("%-5d/tcp   %-10s %-15s\n", port, "open", "syn-ack");
	//     }
	// }
	return 0;
}
