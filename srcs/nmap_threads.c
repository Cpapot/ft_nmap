/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   nmap_threads.c                                     :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: cpapot <cpapot@student.42lyon.fr >         +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/12/01 13:00:38 by cpapot            #+#    #+#             */
/*   Updated: 2025/12/05 14:14:58 by cpapot           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "nmap_threads.h"

t_threads_tasks	*distribute_tasks(t_nmap_data *data)
{
	int	taskPerThread = data->taskCount / data->threadsCount;
	int	remainingTask = data->taskCount % data->threadsCount;

	//printf("task per thread: %d rem: %d\n", taskPerThread, remainingTask);

	t_threads_tasks *distributedTask = stock_malloc(sizeof(t_threads_tasks) * data->threadsCount, &data->allocatedData);
	if (!distributedTask)
		nmap_error(MALLOC_ERROR, data, 1);

	int taskIndex = 0;
	for (int i = 0; i != data->threadsCount; i++)
	{
		distributedTask[i].taskCount = (i == 0) ? taskPerThread + remainingTask : taskPerThread;
		distributedTask[i].threadId = i;
		distributedTask[i].taskList = stock_malloc(sizeof(t_unique_task*) * distributedTask[i].taskCount, &data->allocatedData);
		if (!distributedTask)
			nmap_error(MALLOC_ERROR, data, 1);
		for (int y = 0; y != distributedTask[i].taskCount; y++, taskIndex++)
			distributedTask[i].taskList[y] = &data->uniqueTaskList[taskIndex];
	}

	return distributedTask;
}

void* thread_routine(void *arg)
{
	t_threads_tasks data = *(t_threads_tasks*)arg;
	printf("i am thread %d, and i have %d tasks\n", data.threadId, data.taskCount);
	return NULL;
}

int	launch_threads(t_threads_data *threadsData, t_nmap_data *data)
{
	threadsData->pthreadArray = stock_malloc(sizeof(pthread_t) * data->threadsCount, &data->allocatedData);
	if (!threadsData->pthreadArray)
		nmap_error(MALLOC_ERROR, data, 1);

	for (int i = 0; i != data->threadsCount; i++)
	{
		if (pthread_create(&threadsData->pthreadArray[i], NULL, thread_routine, &threadsData->distributedTasks[i]))
		{
			for (int j = 0; j != i; j++)
				pthread_join(threadsData->pthreadArray[j], NULL);
			nmap_error(THREAD_ERROR, data, 1);
		}
	}

	for (int i = 0; i != data->threadsCount; i++)
		pthread_join(threadsData->pthreadArray[i], NULL);

	return 0;
}
