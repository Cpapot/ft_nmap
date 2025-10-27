/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strlcat.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: cpapot <cpapot@student.42lyon.fr >         +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/11/08 15:44:41 by cpapot            #+#    #+#             */
/*   Updated: 2022/11/30 12:05:21 by cpapot           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../../includes/libft.h"

size_t	ft_strlcat(char *dst, const char *src, size_t size)
{
	unsigned int	i;
	unsigned int	len;

	i = 0;
	if (size == 0)
		return (ft_strlen(src));
	len = ft_strlen(dst);
	if (len + 1 > size)
		return (size + ft_strlen(src));
	while (src[i] != '\0' && len + i < size - 1)
	{
		dst[i + len] = src[i];
		i++;
	}
	dst[i + len] = '\0';
	return (ft_strlen(src) + len);
}
