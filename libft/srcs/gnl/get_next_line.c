/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   get_next_line.c                                    :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: cpapot <cpapot@student.42lyon.fr >         +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/11/15 11:48:15 by cpapot            #+#    #+#             */
/*   Updated: 2023/05/05 16:41:20 by cpapot           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../../includes/get_next_line.h"

static char	*ft_read(char *buf, int fd)
{
	int		buf_len;
	char	*line;
	char	*tmp;

	buf_len = 1;
	line = NULL;
	tmp = malloc(sizeof(char));
	if (!tmp)
		return (NULL);
	tmp[0] = '\0';
	if (buf)
	{
		line = ft_strjoin_gnl(tmp, buf);
		free (tmp);
		if (!line)
			return (NULL);
	}
	tmp = ft_read_line(buf_len, line, buf, fd);
	line = tmp;
	if (!tmp)
		return (NULL);
	return (line);
}

static int	ft_malloc_size(char *line)
{
	int	i;

	i = 0;
	if (line[0] == '\n')
		return (1);
	while (line[i] != '\n' && i < (int)ft_strlen_gnl(line))
		i++;
	return (i + 1);
}

static char	*ft_malloc_line(char *line)
{
	int		i;
	int		u;
	char	*result;

	i = ft_malloc_size(line);
	result = malloc(sizeof(char) * (i + 1));
	if (result == NULL)
		return (free(line), NULL);
	u = 0;
	if (i == 0)
	{
		result[0] = '\0';
		return (free(line), NULL);
	}
	while (i > u)
	{
		result[u] = line[u];
		u++;
	}
	result[u] = '\0';
	return (result);
}

static void	ft_setup_next_line(char *buf, char *line)
{
	int		i;
	int		u;

	i = 0;
	u = 0;
	if (!line)
		return ;
	while (line[i] && line[i] != '\n')
		i++;
	if (line[i] != '\0')
		i++;
	while (line[i + u] != '\0')
	{
		buf[u] = line [i + u];
		u++;
	}
	buf[u] = '\0';
}

char	*get_next_line(int fd)
{
	static char	buf[BUFFER_SIZE_GNL + 1];
	char		*line;
	char		*result;

	if (fd < 0)
		return (NULL);
	line = ft_read(buf, fd);
	if (line == NULL)
		return (NULL);
	result = ft_malloc_line(line);
	if (result == NULL)
		return (free(line), NULL);
	if (result[0] == '\0')
		return (free(line), free(result), NULL);
	ft_setup_next_line(buf, line);
	free(line);
	return (result);
}
