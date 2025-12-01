/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   main.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: cpapot <cpapot@student.42lyon.fr >         +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/11/05 17:06:26 by coco              #+#    #+#             */
/*   Updated: 2025/12/01 14:58:32 by cpapot           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "nmap.h"

int		parsing(int argc, char **argv, t_nmap_data *data);
int		fill_unique_tasks(t_nmap_data *data);

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

	for (int i = 0; i != data.taskCount; i++)
	{
		printf("ip: %s, port: %d, scan; %d\n", data.uniqueTaskList[i].ipToScan, data.uniqueTaskList[i].portToScan, data.uniqueTaskList[i].scanType);
	}
}
