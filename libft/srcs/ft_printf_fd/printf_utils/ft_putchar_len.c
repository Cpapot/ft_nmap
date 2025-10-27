/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_putchar_len.c                                   :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: cpapot <cpapot@student.42lyon.fr >         +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/11/22 11:39:55 by cpapot            #+#    #+#             */
/*   Updated: 2023/02/13 19:18:43 by cpapot           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../ft_printf_fd.h"

ssize_t	ft_putchar_len_fd(int fd, char c)
{
	ssize_t	len;

	len = write(fd, &c, 1);
	return (len);
}
