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

int			setup_timer(t_nmap_data *data);
void 		init_timer(t_nmap_data *data);
long double	stop_timer(t_nmap_data *data);

#endif