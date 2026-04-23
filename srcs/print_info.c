/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   print_info.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: coco <coco@student.42.fr>                  +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/11/24 13:23:37 by cpapot            #+#    #+#             */
/*   Updated: 2026/04/22 16:33:47 by coco             ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "nmap.h"
#include "print_info.h"
#include "timer.h"

# define BUFF_SIZE 1024

static void	str_scan_type(char* res, int *scanType)
{
	ft_bzero(res, 1024 * sizeof(char));

	char **scanTypeList = ft_split_no(SCAN_LIST, ' ');
	if (!scanTypeList)
		return ;

	for(int i = 0; i < 6; i++)
	{
		if (scanType[i] != 0)
		{
			ft_strlcat(res, scanTypeList[i], 1024);
			ft_strlcat(res, " ", 1024);
		}
	}
	ft_free_split(scanTypeList);
}

void	print_config(t_nmap_data *data, char *actualIp)
{
	char	buff[1024];

	long double total_time = stop_timer(data);

	str_scan_type(buff, data->scanType);
	printf("Scans Configurations\n");
	printf("No of Ports to scan : %d\n", data->portsCount);
	printf("Scans to be performed : %s\n", buff);
	printf("No of threads : %d\n", data->threadsCount);
	printf("Ip to scan : %s\n", actualIp);
	printf("Total time taken : %.2Lf ms\n", total_time);
}
