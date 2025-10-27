/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_putunsint_len.c                                 :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: cpapot <cpapot@student.42lyon.fr >         +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/11/22 14:06:02 by cpapot            #+#    #+#             */
/*   Updated: 2022/11/22 15:35:24 by cpapot           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../ft_printf.h"

static int	uintlen(unsigned int n)
{
	int	result;

	result = 0;
	if (n == 0)
		return (1);
	while (n != 0)
	{
		n = n / 10;
		result++;
	}
	return (result);
}

static char	*ft_uitoa(unsigned int n)
{
	int				i;
	char			*result;
	int				u;
	unsigned int	nbr;

	nbr = n;
	i = uintlen(n) - 1;
	u = -1;
	result = malloc(sizeof(char) * (uintlen(n) + 1));
	if (result == 0)
		return (0);
	result[i + 1] = '\0';
	while (i != u)
	{
		result[i] = (nbr % 10) + 48;
		nbr = nbr / 10;
		i--;
	}
	return (result);
}

ssize_t	ft_putunsint_len(unsigned int nbr)
{
	char	*nbr_str;
	ssize_t	len;

	nbr_str = ft_uitoa(nbr);
	len = write(1, nbr_str, ft_strlen(nbr_str));
	free (nbr_str);
	return (len);
}
