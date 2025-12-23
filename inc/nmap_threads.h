/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   nmap_threads.h                                     :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: coco <coco@student.42.fr>                  +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/12/01 12:43:16 by cpapot            #+#    #+#             */
/*   Updated: 2025/12/23 16:35:07 by coco             ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef NMAP_TH_H
# define NMAP_TH_H

# include <pthread.h>
# include "nmap.h"

// params des threads
typedef struct s_threads_tasks
{
	t_port_result		*ports_results;
	t_unique_task		**taskList;
	int					taskCount;
	int					threadId;
}	t_threads_tasks;

typedef struct s_threads_data
{
	t_port_result		*ports_results;
	pthread_t			*pthreadArray;
	t_threads_tasks		*distributedTasks;
}	t_threads_data;

#endif
