/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   main.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: cpapot <cpapot@student.42lyon.fr >         +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/11/05 17:06:26 by coco              #+#    #+#             */
/*   Updated: 2025/11/24 13:59:05 by cpapot           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "nmap.h"

int	parsing(int argc, char **argv, t_nmap_data *data);

void *sniffer_routine(void *arg) {
    (void)arg;
    receiver();
    return NULL;
}

int	main(int argc, char **argv)
{
	t_nmap_data data;
	ft_bzero(&data, sizeof(t_nmap_data));
  pthread_t sniffer_thread;

	if (parsing(argc, argv, &data))
		return 1;

<<<<<<< Updated upstream
	while (data.ips != NULL)
=======
	// while (data.ips != NULL)
	// {
	// 	print_config(&data, data.ips->content);
	// 	data.ips = data.ips->next;
	// }

	fill_unique_tasks(&data);

  if (pthread_create(&sniffer_thread, NULL, sniffer_routine, NULL) != 0)
    return nmap_error("Failed to create sniffer thread", &data, 1);
  sleep(1);
	if (data.threadsCount > 1)
>>>>>>> Stashed changes
	{
		print_config(&data, data.ips->content);
		data.ips = data.ips->next;
	}
<<<<<<< Updated upstream
=======
	else
	{
		for (int i = 0; i != data.taskCount; i++)
		{
			send_tcp_packet(data.uniqueTaskList[i].ipToScan, data.uniqueTaskList[i].portToScan, data.uniqueTaskList[i].scanType);
      usleep(500);
		}
	}
  sleep(2);
  pthread_cancel(sniffer_thread);
  pthread_join(sniffer_thread, NULL);

	// close thread to prevent leaks
	stock_free(&data.allocatedData);
>>>>>>> Stashed changes
}
