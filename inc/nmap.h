/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   nmap.h                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: coco <coco@student.42.fr>                  +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/11/05 17:07:22 by coco              #+#    #+#             */
/*   Updated: 2025/11/05 18:14:05 by coco             ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef NMAP_H
# define NMAP_H

# include "../libft/includes/libft.h"
# include <stdio.h>
# include <stdlib.h>

enum e_nmap_scans_types {
	SYN = 1,
	NULLMODE,
	ACK,
	FIN,
	XMAS,
	UDP
};

typedef struct s_nmap_data
{
	int		scan_type;		// le type de scan SYN, NULL, ACK, FIN, XMAS, UDP
	int		*ports_range;	//count<=1024  default=[1->1024]
	char	**ips;			//array d'ip
	int		threads_count;	//nombre de thread			default = 0
	
	int		exit_status;
}	t_nmap_data;

#endif