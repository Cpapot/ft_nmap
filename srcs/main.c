/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   main.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: cpapot <cpapot@student.42lyon.fr >         +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/11/05 17:06:26 by coco              #+#    #+#             */
/*   Updated: 2025/11/13 15:03:08 by cpapot           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "nmap.h"

int	parsing(int argc, char **argv, t_nmap_data *data);

int	main(int argc, char **argv)
{
	t_nmap_data data;

	ft_bzero(&data, sizeof(t_nmap_data));

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
	printf("\n");
	printf("scan type: %d", data.scan_type);
}
