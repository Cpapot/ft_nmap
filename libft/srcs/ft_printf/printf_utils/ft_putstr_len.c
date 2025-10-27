/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_putstr_len.c                                    :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: cpapot <cpapot@student.42lyon.fr >         +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/11/22 11:43:00 by cpapot            #+#    #+#             */
/*   Updated: 2022/11/23 13:27:50 by cpapot           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../ft_printf.h"

ssize_t	ft_putstr_len(char *str)
{
	ssize_t	len;

	if (str == NULL)
		return (ft_putnull_len());
	len = write(1, str, ft_strlen(str));
	return (len);
}
