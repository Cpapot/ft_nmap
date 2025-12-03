/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   nmap.h                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: cpapot <cpapot@student.42lyon.fr >         +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/11/05 17:07:22 by coco              #+#    #+#             */
/*   Updated: 2025/12/03 15:54:12 by cpapot           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef NMAP_H
# define NMAP_H

# include "../libft/includes/libft.h"
# include <stdio.h>
# include <stdlib.h>

# define ERROR_PRINT "\e[1;31m[ERROR]: \e[0;37m"
# define WARN_PRINT "\e[1;33m[WARN]: \e[0;37m"
# define MALLOC_ERROR "Error during allocation, closing program\n"

# define SCAN_LIST "SYN NULL FIN XMAS ACK UDP"
# define SCAN_COUNT 6
enum e_nmap_scans_types {
	ALL = 0,
	SYN = 1,
	NULLMODE,
	ACK,
	FIN,
	XMAS,
	UDP,
};

typedef struct s_unique_task
{
	char	*ipToScan;
	int		portToScan;
	int		scanType;

}	t_unique_task;

typedef struct s_nmap_data
{
	int				scanType[6];			// le type de scan SYN, NULL, ACK, FIN, XMAS, UDP
	int				scanCount;
	int				ports[1024];		//count<=1024  default=[1->1024]
	int				portsCount;
	t_list			*ips;
	int				ipCount;
	int				threadsCount;		//nombre de thread			default = 0

	t_unique_task	*uniqueTaskList;
	int				taskCount;



	t_memlist		*allocatedData;
	int				exitStatus;
}	t_nmap_data;

void	print_config(t_nmap_data *data, char *actualIp);
int		nmap_error(char *error, t_nmap_data *data, int doExit);


#endif
