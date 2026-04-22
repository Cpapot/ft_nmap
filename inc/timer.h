/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   timer.h                                            :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: coco <coco@student.42.fr>                  +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/03/20 18:55:18 by cpapot            #+#    #+#             */
/*   Updated: 2026/04/22 16:02:15 by coco             ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef TIMER_H
# define TIMER_H

# include "nmap.h"
# include <time.h>
# include <sys/time.h>
# include <math.h>


typedef struct s_time_data
{
	long double		actual_delay;
	long double		total_delay;
} t_time_data;

int			setup_timer(t_nmap_data *data);
void 		init_timer(void);
long double	stop_timer(void);


#endif