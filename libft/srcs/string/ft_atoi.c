/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_atoi.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: cpapot <cpapot@student.42lyon.fr >         +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/11/08 14:19:00 by cpapot            #+#    #+#             */
/*   Updated: 2023/09/26 21:52:21 by cpapot           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../../includes/libft.h"

int	overflow(int sign)
{
	if (sign == -1)
		return (0);
	else
		return (-1);
}

int	ft_atoi(const char *str)
{
	long long int	result;
	int				minus;

	result = 0;
	minus = 0;
	while ((*str >= 9 && *str <= 13) || *str == 32)
		str++;
	if (*str == '-' || *str == '+')
	{
		if (*str == '-')
			minus--;
		str++;
	}
	while ('9' >= *str && '0' <= *str)
	{
		if (result != (result * 10 + (*str - '0')) / 10)
			return ((int) overflow(minus));
		result = result * 10 + (*str - 48);
		str++;
	}
	if (minus == -1)
		result = -result;
	return ((int)result);
}

bool	ft_atoi_on(const char *str, int *dst)
{
	long long int	result;
	int				minus;

	result = 0;
	minus = 0;
	while ((*str >= 9 && *str <= 13) || *str == 32)
		str++;
	if (*str == '-' || *str == '+')
	{
		if (*str == '-')
			minus--;
		str++;
	}
	while ('9' >= *str && '0' <= *str)
	{
		if (result != (result * 10 + (*str - '0')) / 10)
			return (false);
		result = result * 10 + (*str - 48);
		str++;
	}
	if (minus == -1)
		result = -result;
	*dst = (int)result;
	return (true);
}
