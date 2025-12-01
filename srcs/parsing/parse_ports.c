/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   parse_ports.c                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: cpapot <cpapot@student.42lyon.fr >         +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/11/24 09:17:24 by cpapot            #+#    #+#             */
/*   Updated: 2025/12/01 14:31:53 by cpapot           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "parsing.h"

// return false if max ports (1024) is exceed
static bool	add_port(int ports[1024], int *port_count, int portToAdd)
{
	for (int i = 0; i != 1024; i++)
	{
		if (ports[i] == 0)
		{
			(*port_count)++;
			ports[i] = portToAdd;
			return true;
		}
	}
	return false;
}

static int parse_ports_range(t_nmap_data *data, char* range, char *portsStr)
{
	char **splittedRange = ft_split_no(range, '-');
	if (!splittedRange)
		return parsing_error(data, MALLOC_ERROR, NULL, 1);

	if (!(splittedRange[0] && splittedRange[1] && splittedRange[2] == NULL))
	{
		ft_free_split(splittedRange);
		return parsing_error(data, INVALID_PORT, portsStr, 1);
	}
	int startPort = ft_atoi(splittedRange[0]);
	int endPort = ft_atoi(splittedRange[1]);

	if (startPort <= 0 || startPort >= 65535 || endPort <= 0 || endPort >= 65535)
	{
		ft_free_split(splittedRange);
		return parsing_error(data, INVALID_PORT, portsStr, 1);
	}

	if (startPort >= endPort)
	{
		ft_free_split(splittedRange);
		return parsing_error(data, INVALID_PORT, portsStr, 1);
	}
	ft_free_split(splittedRange);

	for (int range = startPort; range <= endPort; range++)
	{
		if (!add_port(data->ports, &data->portsCount, range))
		{
			printf("%s%s", WARN_PRINT, MAX_PORT_REACHED);
			return 2;
		}
	}
	return 0;
}

int	parse_ports(char *portsStr, t_nmap_data *data)
{
	char **portSplit = ft_split_no(portsStr, ',');
	if (!portSplit)
		return parsing_error(data, MALLOC_ERROR, NULL, 1);

	for (int i = 0; portSplit[i] != NULL; i++)
	{
		if (is_in_string('-', portSplit[i]))
		{
			int res = parse_ports_range(data, portSplit[i], portsStr);
			if (res == 1 || res == 2) // res == 1 erreur on quitte (normalement allocated data deja free) res == 2 warn on arrete le parsing des ports mais on ne quitte pas
			{
				ft_free_split(portSplit);
				return (res == 1 ? 1 : 0);
			}
		}
		else
		{
			if (!is_all_numbers(portSplit[i]))
			{
				ft_free_split(portSplit);
				return parsing_error(data, INVALID_PORT, portsStr, 1);
			}
			int port = ft_atoi(portSplit[i]);
			if (port <= 0 || port >= 65535)
			{
				ft_free_split(portSplit);
				return parsing_error(data, INVALID_PORT, portsStr, 1);
			}

			if (!add_port(data->ports, &data->portsCount ,port))
			{
				ft_free_split(portSplit);
				printf("%s%s", WARN_PRINT, MAX_PORT_REACHED);
				return 0;
			}
		}
	}
	ft_free_split(portSplit);
	return 0;
}
