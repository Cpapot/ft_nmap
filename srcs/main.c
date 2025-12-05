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
int		receiver();



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
	ft_bzero(&data, sizeof(t_nmap_data));

	if (parsing(argc, argv, &data))
		return 1;

	// while (data.ips != NULL)
	// {
	// 	print_config(&data, data.ips->content);
	// 	data.ips = data.ips->next;
	// }

	fill_unique_tasks(&data);
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
			receiver();
		}
	}

	// close thread to prevent leaks
	stock_free(&data.allocatedData);
}
