/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   timer.c                                            :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: coco <coco@student.42.fr>                  +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/03/20 18:53:41 by cpapot            #+#    #+#             */
/*   Updated: 2026/04/22 16:45:44 by coco             ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "timer.h"

/**
 * @brief Initializes the timer data structure for tracking packet timing
 * @param data Pointer to nmap data structure for memory allocation tracking & timing data
 * @return 0 on success, 1 on allocation failure
 */
int setup_timer(t_nmap_data *data)
{
	if (data->time_data == NULL)
	{
		data->time_data = stock_malloc(sizeof(t_time_data), &data->allocatedData);
		if (data->time_data == NULL)
			nmap_error(MALLOC_ERROR, data, 1);
		data->time_data->total_delay = 0;
	}
	return 0;
}

/**
 * @brief Starts a timing operation by capturing the current time
 * @param data Pointer to nmap data structure for memory allocation tracking & timing data& timing data
 */
void init_timer(t_nmap_data *data)
{
	struct timeval timer;

	gettimeofday(&timer, NULL);
	data->time_data->actual_delay = (long double)(timer.tv_usec * 0.001 + timer.tv_sec * 1000);
}

/**
 * @brief Stops timing operation and calculates elapsed time since init_timer call
 * @param data Pointer to nmap data structure for memory allocation tracking & timing data
 * @return Elapsed time in milliseconds
 */
long double stop_timer(t_nmap_data *data)
{
	struct timeval timer;

	gettimeofday(&timer, NULL);
	data->time_data->actual_delay = (long double)((timer.tv_usec * 0.001 + timer.tv_sec * 1000)) - data->time_data->actual_delay;
	return data->time_data->actual_delay;
}