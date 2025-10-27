/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_findformat.c                                    :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: cpapot <cpapot@student.42lyon.fr >         +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/11/22 15:44:54 by cpapot            #+#    #+#             */
/*   Updated: 2022/11/25 18:22:57 by cpapot           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../ft_printf.h"

#include "../ft_printf.h"

ssize_t	ft_skipword(char const *format, int index)
{
	int		wordsize;
	ssize_t	len;
	char	*word;

	wordsize = 0;
	while (format[index] != '\0' && format[index] != '%')
	{
		index++;
		wordsize++;
	}
	if (wordsize != 0)
	{
		word = ft_substr(format, index - wordsize, wordsize);
		if (!word)
			return (-1);
		len = ft_putstr_len(word);
		free (word);
		return (len);
	}
	return (0);
}

static ssize_t	ft_findformat(char const *format, int index, va_list variadic)
{
	ssize_t	len;

	len = 0;
	index = index + 2;
	if (format[index - 1] == 'c')
		return (ft_putchar_len(va_arg(variadic, int)));
	if (format[index - 1] == 's')
		return (ft_putstr_len(va_arg(variadic, char *)));
	if (format[index - 1] == 'p')
		return (ft_puthexavoid_len(va_arg(variadic, void *)));
	if (format[index - 1] == 'd')
		return (ft_putint_len(va_arg(variadic, int)));
	if (format[index - 1] == 'i')
		return (ft_putint_len(va_arg(variadic, int)));
	if (format[index - 1] == 'u')
		return (ft_putunsint_len(va_arg(variadic, unsigned int)));
	if (format[index - 1] == 'x')
		return (ft_puthexamin_len(va_arg(variadic, unsigned int)));
	if (format[index - 1] == 'X')
		return (ft_puthexamaj_len(va_arg(variadic, unsigned int)));
	if (format[index - 1] == '%')
		return (ft_putpercent_len());
	return (len);
}

ssize_t	ft_callformat(char const *format, va_list variadic)
{
	ssize_t		tmp;
	ssize_t		len;
	int			index;

	len = 0;
	index = 0;
	while (format[index] != '\0')
	{
		tmp = 0;
		tmp = ft_skipword(format, index);
		index = tmp + index;
		if (tmp == -1)
			return (-1);
		len = len + tmp;
		tmp = 0;
		if (format[index] == '%' && format[index + 1] != '\0')
		{
			tmp = ft_findformat(format, index, variadic);
			index = index + 2;
		}
		if (tmp == -1)
			return (-1);
		len = len + tmp;
	}
	return (len);
}
