/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   parsing.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: cpapot <cpapot@student.42lyon.fr >         +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/11/05 17:23:42 by coco              #+#    #+#             */
/*   Updated: 2025/11/13 15:05:08 by cpapot           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "parsing.h"

char *resolve_host(const char *host);

int	find_flag(char *flagsLine)
{
	char **flags = ft_split_no(FLAGS_LIST, ' ');
	//checkNUll

	for (int i = 0; i != FLAG_COUNT; i++)
	{
		if (ft_strcmp(flagsLine, flags[i]))
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
bool	add_port(int ports[1024], int *port_count, int portToAdd)
{
	for (int i = 0; i != 1024; i++)
	{
		if (ports[i] == 0)
		{
			port_count++;
			ports[i] = portToAdd;
			return true;
		}
	}
	return false;
}

//ajouter une fonction de parsing pour chaque flag (parseFile(), parsePorts()......)

// return 0 si ok return 1 si error
// to do : decomposer la fonction
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

			if (!(portsRange[0] && portsRange[1] && portsRange[2] == NULL))
			{
				printf(INVALID_PORT, portsStr);
				return 1;
			}
			int startPort = ft_atoi(portsRange[0]);
			int endPort = ft_atoi(portsRange[1]);

			if (startPort >= endPort)
			{
				printf(INVALID_PORT, portsStr);
				return 1;
			}
			ft_free_split(portsRange);

			for (int range = startPort; range <= endPort; range++)
			{
				if (!add_port(data->ports, &data->ports_count, range))
				{
					printf(MAX_PORT_REACHED);
					return 0;
				}
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
			if (!add_port(data->ports, &data->ports_count ,port))
			{
				printf(MAX_PORT_REACHED);
				return 0;
			}
		}
	}
	ft_free_split(portSplit);
	return 0;
}

int	parse_ip(char *ipStr, t_nmap_data *data)
{
	char *host = resolve_host(ipStr);
	if (host != NULL)
	{
		char *ip = ft_strdup(host, &data->allocated_data);
		//check null
		ft_lstadd_back(&data->ips, ft_lstnew(ip, &data->allocated_data));
	}
	else
	{
		printf(UNKNOWN_HOST, ipStr);
		return 1;
	}
	return 0;
}

int	parse_file(char *filePath, t_nmap_data *data)
{
	char	*line;
	int		fd = open(filePath, O_RDONLY);
	if (fd == -1)
	{
		printf(CANT_OPEN_FILE, filePath);
		return 1;
	}
	while ((line = get_next_line(fd)) != NULL)
	{
		size_t	len = ft_strlen(line);
		if (len == 1 && line[0] == '\n')
			continue;

		if (len != 0)
		{
			line[len - 1] = 0;
			parse_ip(line, data);
			// check null
		}
		free(line);
	}
	close(fd);
	return 0;
}

int	parse_speedup(char *threadCount, t_nmap_data *data)
{
	if (is_all_numbers(threadCount) == false)
	{
		printf(INVALID_SPEEDUP_PARAMETER, threadCount);
		return 1;
	}
	int count = ft_atoi(threadCount);
	if (count > 1 && count >= 255)
	{
		printf(INVALID_THREAD_COUNT);
		return 1;
	}
	data->threads_count = count;
	return 0;
}

int	parse_scan(char *scanType, t_nmap_data *data)
{
	char **scanTypeList = ft_split_no(SCAN_LIST, ' ');
	//checkNUll

	for (int i = 0; i != FLAG_COUNT; i++)
	{
		if (ft_strcmp(scanType, scanTypeList[i]))
		{
			ft_free_split(scanTypeList);
			data->scan_type = i + 1;
			return 0;
		}
	}
	ft_free_split(scanTypeList);
	printf(UNKNOWN_SCAN, scanType);
	return 1;
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
					if (++i >= argc)
					{
						printf(MISSING_ARG, argv[i - 1]);
						return 1;
					}
					parse_ports(argv[i], data);
					break;
				case IP_F:
					if (++i >= argc)
					{
						printf(MISSING_ARG, argv[i - 1]);
						return 1;
					}
					parse_ip(argv[i], data);
					break;
				case FILE_F:
					if (++i >= argc)
					{
						printf(MISSING_ARG, argv[i - 1]);
						return 1;
					}
					parse_file(argv[i], data);
					break;
				case SPEEDUP_F:
					if (++i >= argc)
					{
						printf(MISSING_ARG, argv[i - 1]);
						return 1;
					}
					parse_speedup(argv[i], data);
					break;
				case SCAN_F:
					if (++i >= argc)
					{
						printf(MISSING_ARG, argv[i - 1]);
						return 1;
					}
					parse_scan(argv[i], data);
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
	if (data->ips == NULL)
	{
		printf(NO_IP);
		return 1;
	}
	return 0;
}
// si ips est vide a la fin du parsing alors erreur
