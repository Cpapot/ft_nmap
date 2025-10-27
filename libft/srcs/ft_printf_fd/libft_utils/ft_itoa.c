/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_itoa.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: cpapot <cpapot@student.42lyon.fr >         +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/11/11 11:09:49 by cpapot            #+#    #+#             */
/*   Updated: 2023/01/18 20:09:21 by cpapot           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../ft_printf_fd.h"

static int	intlen(int n)
{
	int	result;

	result = 0;
	if (n == 0)
		return (1);
	if (n < 0)
	{
		n = -n;
		result++;
	}
	while (n != 0)
	{
		n = n / 10;
		result++;
	}
	return (result);
}

char	*ft_itoa(int n)
{
	int		i;
	char	*result;
	int		u;
	long	nbr;

	nbr = n;
	i = intlen(n) - 1;
	u = -1;
	result = malloc(sizeof(char) * (intlen(n) + 1));
	if (result == 0)
		return (0);
	if (nbr < 0)
	{
		result[0] = '-';
		nbr = -nbr;
		u = 0;
	}
	result[i + 1] = '\0';
	while (i != u)
	{
		result[i] = (nbr % 10) + 48;
		nbr = nbr / 10;
		i--;
	}
	return (result);
}
