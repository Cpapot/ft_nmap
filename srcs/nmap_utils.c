/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   nmap_utils.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: cpapot <cpapot@student.42lyon.fr >         +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/12/01 13:13:46 by cpapot            #+#    #+#             */
/*   Updated: 2025/12/01 14:59:41 by cpapot           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "nmap.h"

int		fill_unique_tasks(t_nmap_data *data)
{
	data->taskCount = data->portsCount * data->scanCount * data->ipCount;
	data->uniqueTaskList = stock_malloc((sizeof(t_unique_task)*data->taskCount), &data->allocatedData);
	//check NULL
	int		taskIndex = 0;
	t_list	*ipsList = data->ips;

	for (int i = 0; i != data->ipCount; i++)
	{
		char *actualIp = ipsList->content;
		int		scanIndex = 0;
		for (int y = 0; y != data->scanCount; y++)
		{
			while (scanIndex != 6)
			{
				if (data->scanType[scanIndex] == 1)
					break;
				scanIndex++;
			}

			for (int x = 0; x != data->portsCount; x++)
			{
				data->uniqueTaskList[taskIndex].ipToScan = actualIp;
				data->uniqueTaskList[taskIndex].portToScan = data->ports[x];
				data->uniqueTaskList[taskIndex].scanType = scanIndex + 1;

				taskIndex++;
			}
			scanIndex++;
		}
		ipsList = ipsList->next;
	}

	return 0;
}
