/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   get_next_line.h                                    :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: cpapot <cpapot@student.42lyon.fr >         +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/11/15 11:48:19 by cpapot            #+#    #+#             */
/*   Updated: 2023/05/05 16:41:07 by cpapot           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef GET_NEXT_LINE_H

# define GET_NEXT_LINE_H

# include <unistd.h>
# include <stdlib.h>
# include <sys/types.h>
# include <sys/stat.h>
# include <fcntl.h>
# include <unistd.h>

# ifndef BUFFER_SIZE_GNL

#  define BUFFER_SIZE_GNL 20

# endif

size_t	ft_strlen_gnl(const char *str);
void	ft_bzero_gnl(void *s, size_t n);
char	*ft_strjoin_gnl(char *s1, char const *s2);
int		ft_line_end(char *line);
char	*ft_read_line(int buf_len, char *line, char *buf, int fd);
char	*get_next_line(int fd);

#endif
