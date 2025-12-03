/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   nmap_threads.h                                     :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: cpapot <cpapot@student.42lyon.fr >         +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/12/01 12:43:16 by cpapot            #+#    #+#             */
/*   Updated: 2025/12/03 15:22:06 by cpapot           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef NMAP_TH_H
# define NMAP_TH_H

# include <pthread.h>
# include "nmap.h"

// params des threads
typedef struct s_threads_tasks
{
	t_unique_task		**taskList;
	int					taskCount;
	int					threadId;
}	t_threads_tasks;

typedef struct s_threads_data
{
	pthread_t			*pthreadArray;
	t_threads_tasks		*distributedTasks;
}	t_threads_data;

#endif
