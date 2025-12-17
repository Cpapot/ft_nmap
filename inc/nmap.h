/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   nmap.h                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: cpapot <cpapot@student.42lyon.fr >         +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/11/05 17:07:22 by coco              #+#    #+#             */
/*   Updated: 2025/12/05 14:00:05 by cpapot           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef NMAP_H
# define NMAP_H

# include "../libft/includes/libft.h"
# include <stdio.h>
# include <stdlib.h>
# include <netdb.h>

# define ERROR_PRINT "\e[1;31m[ERROR]: \e[0;37m"
# define WARN_PRINT "\e[1;33m[WARN]: \e[0;37m"
# define MALLOC_ERROR "Error during allocation, closing program\n"
# define THREAD_ERROR "Error during threads creation, closing program\n"

# define SCAN_LIST "SYN NULL FIN XMAS ACK UDP"
# define SCAN_COUNT 6

typedef enum e_nmap_scans_types {
	ALL = 0,
	SYN,
	NULLMODE,
	ACK,
	FIN,
	XMAS,
	UDP,
} e_nmap_scans_types;

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

// Statut des ports
typedef enum {
    PORT_OPEN = 0,
    PORT_CLOSED,
    PORT_FILTERED,
    PORT_OPEN_FILTERED,
    PORT_UNFILTERED
} e_port_status;

typedef struct s_scan_result {
    e_nmap_scans_types  type;
    e_port_status state;
    bool          answered;   // 0/1
}   t_scan_result;

typedef struct s_port_result {
    uint16_t        port;
    t_scan_result   scans[SCAN_COUNT]; // indexé par type de scan
}   t_port_result;

// Paramètres de scan (passer en argument aux fonctions de scan)
typedef struct s_scan_params {
    char *target_ip;
    uint16_t port;
    char *source_ip;  // Pour le spoofing (bonus)
    int timeout_ms;
} t_scan_params;

void	print_config(t_nmap_data *data, char *actualIp);
int		nmap_error(char *error, t_nmap_data *data, int doExit);


#endif
