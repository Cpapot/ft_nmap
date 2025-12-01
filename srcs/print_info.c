/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   print_info.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: cpapot <cpapot@student.42lyon.fr >         +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/11/24 13:23:37 by cpapot            #+#    #+#             */
/*   Updated: 2025/12/01 14:13:45 by cpapot           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "nmap.h"
#include "print_info.h"

static void	str_scan_type(char* res, int *scanType)
{
	ft_bzero(res, 256 * sizeof(char));

	char **scanTypeList = ft_split_no(SCAN_LIST, ' ');
	if (!scanTypeList)
		return ;

	for(int i = 0; i < 6; i++)
	{
		if (scanType[i] != 0)
		{
			ft_strlcat(res, scanTypeList[i], 256);
			ft_strlcat(res, " ", 256);
		}
	}
	ft_free_split(scanTypeList);
}

void	print_config(t_nmap_data *data, char *actualIp)
{
	char	buff[256];

	str_scan_type(buff, data->scanType);
	printf("Scan Configurations\n");
	printf("Target Ip-Address : %s\n", actualIp);
	printf("No of Ports to scan : %d\n", data->portsCount);
	printf("Scans to be performed : %s\n", buff);
	printf("No of threads : %d\n", data->threadsCount);
}
