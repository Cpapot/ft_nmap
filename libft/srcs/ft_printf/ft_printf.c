/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_printf.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: cpapot <cpapot@student.42lyon.fr >         +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/11/24 10:48:33 by cpapot            #+#    #+#             */
/*   Updated: 2023/01/18 19:55:58 by cpapot           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_printf.h"

int	ft_printf(const char *format, ...)
{
	ssize_t	len;
	va_list	variadic;

	va_start(variadic, format);
	len = ft_callformat(format, variadic);
	va_end(variadic);
	return ((int)len);
}
