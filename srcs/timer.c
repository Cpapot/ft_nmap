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

t_time_data *time_data = NULL;

/**
 * @brief Initializes the timer data structure for tracking packet timing
 * @param data Pointer to nmap data structure for memory allocation tracking
 * @return 0 on success, 1 on allocation failure
 */
int setup_timer(t_nmap_data *data)
{
	if (time_data == NULL)
	{
		time_data = stock_malloc(sizeof(t_time_data), &data->allocatedData);
		if (time_data == NULL)
			nmap_error(MALLOC_ERROR, data, 1);
		time_data->total_delay = 0;
	}
	return 0;
}

/**
 * @brief Starts a timing operation by capturing the current time
 */
void init_timer(void)
{
	struct timeval timer;

	gettimeofday(&timer, NULL);
	time_data->actual_delay = (long double)(timer.tv_usec * 0.001 + timer.tv_sec * 1000);
}

/**
 * @brief Stops timing operation and calculates elapsed time since init_timer call
 * @return Elapsed time in milliseconds
 */
long double stop_timer(void)
{
	struct timeval timer;

	gettimeofday(&timer, NULL);
	time_data->actual_delay = (long double)((timer.tv_usec * 0.001 + timer.tv_sec * 1000)) - time_data->actual_delay;
	return time_data->actual_delay;
}