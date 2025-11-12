/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   main.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: cpapot <cpapot@student.42lyon.fr >         +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/11/05 17:06:26 by coco              #+#    #+#             */
/*   Updated: 2025/11/12 15:55:34 by cpapot           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "nmap.h"

int	parsing(int argc, char **argv, t_nmap_data *data);

int	main(int argc, char **argv)
{
	t_nmap_data data;

	ft_bzero(&data.ports, sizeof(int) * 1024);
	data.allocated_data = NULL;
	data.ports_count = 0;
	data.ips = NULL;

	parsing(argc, argv, &data);

	for (int i = 0; i != 1024 && data.ports[i] != 0; i++)
	{
		printf("%d, ", data.ports[i]);
	}
	printf("\n");
	t_list *lst = data.ips;
	while (lst)
	{
		printf("%s\n", lst->content);
		lst = lst->next;
	}
}
