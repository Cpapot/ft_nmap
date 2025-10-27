/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_putint_len.c                                    :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: cpapot <cpapot@student.42lyon.fr >         +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/11/22 13:39:34 by cpapot            #+#    #+#             */
/*   Updated: 2023/02/13 19:19:08 by cpapot           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../ft_printf_fd.h"

ssize_t	ft_putint_len_fd(int fd, int nbr)
{
	ssize_t	len;
	char	*nbr_str;

	nbr_str = ft_itoa(nbr);
	len = write(fd, nbr_str, ft_strlen(nbr_str));
	free(nbr_str);
	return (len);
}
