/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_puthexavoid_len.c                               :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: cpapot <cpapot@student.42lyon.fr >         +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/11/23 17:32:26 by cpapot            #+#    #+#             */
/*   Updated: 2022/11/24 13:18:01 by cpapot           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../ft_printf.h"

static int	ft_hexa_size(uintptr_t nbr)
{
	int	index;

	index = 0;
	while (nbr >= 16)
	{
		nbr = nbr / 16;
		index++;
	}
	if (nbr != 0)
		index++;
	return (index);
}

static char	*ft_convert_hexa(uintptr_t nbr)
{
	char	*base;
	char	*result;
	int		size;
	int		index;

	base = "0123456789abcdef";
	size = ft_hexa_size(nbr);
	result = malloc(sizeof(char) * (size + 1));
	if (result == NULL)
		return (NULL);
	index = size - 1;
	ft_bzero(result, size + 1);
	while (nbr >= 16)
	{
		result[index] = base[nbr % 16];
		nbr = nbr / 16;
		index--;
	}
	if (nbr != 0)
		result[index] = base[nbr % 16];
	result[size] = '\0';
	return (result);
}

ssize_t	ft_puthexavoid_len(void *arg)
{
	ssize_t	len;
	char	*str;

	if (arg == NULL)
	{
		str = malloc(sizeof(char) * 2);
		if (!str)
			return (-1);
		str[0] = '0';
		str[1] = '\0';
	}
	else
	{
		str = ft_convert_hexa((uintptr_t)arg);
		if (!str)
			return (-1);
	}
	len = write(1, "0x", 2);
	if (len == -1)
		return (len);
	len = len + write(1, str, ft_strlen(str));
	free (str);
	return (len);
}
