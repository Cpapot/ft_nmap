/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   parsing.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: coco <coco@student.42.fr>                  +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/11/05 17:23:42 by coco              #+#    #+#             */
/*   Updated: 2025/11/07 16:33:51 by coco             ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "parsing.h"

int	find_flag(char *flags_line)
{
	char **flags = ft_split_no(FLAGS_LIST, ' ');
	//checkNUll
	
	for (int i = 0; i != FLAG_COUNT; i++)
	{
		if (ft_strcmp(flags_line, flags[i]))
		{
			ft_free_split(flags);
			return i + 1;
		}
	}
	ft_free_split(flags);
	return UNKNOWN_F;
}

// return false if max ports (1024) is exceed 
// portToAdd != 0
bool	add_port(int ports[1024], int portToAdd)
{
	for (int i = 0; i != 1024; i++)
	{
		if (ports[i] == 0)
		{
			ports[i] = portToAdd;
			return true;
		}
	}
	return false;
}

//ajouter une fonction de parsing pour chaque flag (parseFile(), parsePorts()......)

// si on a + de 1024 port ne pas return d'erreur mais un warning qui dit que tous les ports ne seront pas scanné
// return 0 si ok return 1 si error
int	parse_ports(char *portsStr, t_nmap_data *data)
{
	//maybe check si dans la string on a que des nbr , et -
	char **portSplit = ft_split_no(portsStr, ',');
	//checkNUll
	
	for (int i = 0; portSplit[i] != NULL; i++)
	{
		
		if (is_in_string('-', portSplit[i]))
		{
			char **portsRange = ft_split_no(portSplit[i], '-');
			//checkNUll
			
			// check si size(portRange) == 2
			// et startPort < endPort
			// et (port == 0 || port >= 65535)
			int startPort = ft_atoi(portsRange[0]);
			int endPort = ft_atoi(portsRange[1]);
			ft_free_split(portsRange);

			for (int range = startPort; range <= endPort; range++)
			{
				add_port(data->ports, range);
				//check warning
			}
		}
		else
		{
			if (!is_all_numbers(portSplit[i]))
			{
				ft_free_split(portSplit);
				return 1;
			}
			int port = ft_atoi(portSplit[i]);
			/*if (port == 0 || port >= 65535)
				//invalid port
			*/
			add_port(data->ports, port);
			//check warning
		}
	}
	return 0;
}

// return 0 si le prog doit continuer 1 si on doit fermer
int	parsing(int argc, char **argv, t_nmap_data *data)
{
	for (int i = 1; i != argc; i++)
	{
		if (is_flags(argv[i]))
		{
			int flagId = find_flag(argv[i]);
			switch (flagId)
			{
				case UNKNOWN_F:
					printf(UNKNOWN_FLAG, argv[i]);
					return 1;
				case PORTS_F:
					i++;
					parse_ports(argv[i], data);
					break;
				default :
					printf("%d\n", flagId);
					break;
			}
		}
		else
		{
			printf(UNKNOWN_PARAM, argv[i]);
			return 1;
		}
	}
	return 1;
}