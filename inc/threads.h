/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   threads.h                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: cpapot <cpapot@student.42lyon.fr >         +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/12/01 12:43:16 by cpapot            #+#    #+#             */
/*   Updated: 2025/12/01 13:11:06 by cpapot           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef THREADS_H
# define THREADS_H

# include <pthread.h>
# include "nmap.h"

typedef struct s_threads_tasks
{
	t_unique_task		*taskList;
}	t_threads_tasks;

#endif
