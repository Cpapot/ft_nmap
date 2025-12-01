/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   parsing.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: cpapot <cpapot@student.42lyon.fr >         +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/11/05 17:23:42 by coco              #+#    #+#             */
/*   Updated: 2025/12/01 14:13:40 by cpapot           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "parsing.h"

char	*resolve_host(const char *host);
int		parse_ports(char *portsStr, t_nmap_data *data);


int	find_flag(char *flagsLine)
{
	char **flags = ft_split_no(FLAGS_LIST, ' ');
	if (!flags)
		return parsing_error(NULL, MALLOC_ERROR, NULL, -1);

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

int	parse_ip(char *ipStr, t_nmap_data *data)
{
	char *host = resolve_host(ipStr);
	if (host != NULL)
	{
		char *ip = ft_strdup(host, &data->allocatedData);
		if (!ip)
			return parsing_error(data, MALLOC_ERROR, NULL, 1);
		t_list *lst = ft_lstnew(ip, &data->allocatedData);
		if (!lst)
			return parsing_error(data, MALLOC_ERROR, NULL, 1);
		ft_lstadd_back(&data->ips, lst);
	}
	else
		return parsing_error(data, UNKNOWN_HOST, ipStr, 1);
	return 0;
}

int	parse_file(char *filePath, t_nmap_data *data)
{
	char	*line;
	int		fd = open(filePath, O_RDONLY);
	if (fd == -1)
		return parsing_error(data, CANT_OPEN_FILE, filePath, 1);
	while ((line = get_next_line(fd)) != NULL)
	{
		size_t	len = ft_strlen(line);
		if (len == 1 && line[0] == '\n')
			continue;

		if (len != 0)
		{
			line[len - 1] = 0;
			if (parse_ip(line, data))
				return 1;
		}
		free(line);
	}
	close(fd);
	return 0;
}

int	parse_speedup(char *threadCount, t_nmap_data *data)
{
	if (is_all_numbers(threadCount) == false)
		return parsing_error(data, INVALID_SPEEDUP_PARAMETER, threadCount, 1);
	int count = ft_atoi(threadCount);
	if (count < 0 || count > 255)
		return parsing_error(data, INVALID_THREAD_COUNT, NULL, 1);
	data->threadsCount = count;
	return 0;
}

int	parse_scan(char *scanType, t_nmap_data *data)
{
	char **scanTypeList = ft_split_no(SCAN_LIST, ' ');
	if (!scanTypeList)
		return parsing_error(data, MALLOC_ERROR, NULL, 1);

	char **scanTypeInputList = ft_split_no(scanType, ',');
	if (!scanTypeInputList)
	{
		ft_free_split(scanTypeList);
		return parsing_error(data, MALLOC_ERROR, NULL, 1);
	}

	for (int i = 0; scanTypeInputList[i]; i++)
	{
		for (int y = 0; y != FLAG_COUNT; y++)
		{
			if (ft_strcmp(scanTypeInputList[i], scanTypeList[y]))
			{
				data->scanType[y] = 1;
				break;
			}
			if (y + 1 == FLAG_COUNT)
			{
				ft_free_split(scanTypeList);
				ft_free_split(scanTypeInputList);
				return parsing_error(data, UNKNOWN_SCAN, scanType, 1);
			}
		}
	}
	ft_free_split(scanTypeInputList);
	ft_free_split(scanTypeList);
	return 0;
}

// return 0 si le prog doit continuer 1 si on doit fermer
// to do add help
int	parsing(int argc, char **argv, t_nmap_data *data)
{
	for (int i = 1; i != argc; i++)
	{
		if (is_flags(argv[i]))
		{
			int flagId = find_flag(argv[i]);
			switch (flagId)
			{
				case -1:
					return 1;
				case UNKNOWN_F:
					return parsing_error(data, UNKNOWN_FLAG, argv[i], 1);
				case PORTS_F:
					if (++i >= argc || is_flags(argv[i]))
						return parsing_error(data, MISSING_ARG, argv[i - 1], 1);
					if (parse_ports(argv[i], data))
						return 1;
					break;
				case IP_F:
					if (++i >= argc || is_flags(argv[i]))
						return parsing_error(data, MISSING_ARG, argv[i - 1], 1);
					if (parse_ip(argv[i], data))
						return 1;
					break;
				case FILE_F:
					if (++i >= argc || is_flags(argv[i]))
						return parsing_error(data, MISSING_ARG, argv[i - 1], 1);
					if (parse_file(argv[i], data))
						return 1;
					break;
				case SPEEDUP_F:
					if (++i >= argc || is_flags(argv[i]))
						return parsing_error(data, MISSING_ARG, argv[i - 1], 1);
					if (parse_speedup(argv[i], data))
						return 1;
					break;
				case SCAN_F:
					if (++i >= argc || is_flags(argv[i]))
						return parsing_error(data, MISSING_ARG, argv[i - 1], 1);
					if (parse_scan(argv[i], data))
						return 1;
					break;
				case HELP_F:
					printf(HELP_FLAG);
					stock_free(&data->allocatedData);
					return 1;
			}
		}
		else
			return parsing_error(data, UNKNOWN_PARAM, argv[i], 1);
	}
	if (data->ips == NULL)
		return parsing_error(data, NO_IP, NULL, 1);
	if (data->ports[0] == 0)
	{
		data->portsCount = 1024;
		for (int i = 0; i != 1024; i++)
			data->ports[i] = i + 1;
	}
	return 0;
}
