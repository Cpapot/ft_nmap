/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   main.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: coco <coco@student.42.fr>                  +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/11/05 17:06:26 by coco              #+#    #+#             */
/*   Updated: 2025/11/07 16:10:08 by coco             ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "nmap.h"

int	parsing(int argc, char **argv, t_nmap_data *data);

int	main(int argc, char **argv)
{
	t_nmap_data data;

	ft_bzero(&data.ports, sizeof(int) * 1024);
	
	parsing(argc, argv, &data);

	for (int i = 0; i != 1024 && data.ports[i] != 0; i++)
	{
		printf("%d, ", data.ports[i]);
	}
}