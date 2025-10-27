/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_putstr_len.c                                    :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: cpapot <cpapot@student.42lyon.fr >         +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/11/22 11:43:00 by cpapot            #+#    #+#             */
/*   Updated: 2023/02/13 19:24:26 by cpapot           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../ft_printf_fd.h"

ssize_t	ft_putstr_len_fd(int fd, char *str)
{
	ssize_t	len;

	if (str == NULL)
		return (ft_putnull_len_fd(fd));
	len = write(fd, str, ft_strlen(str));
	return (len);
}
