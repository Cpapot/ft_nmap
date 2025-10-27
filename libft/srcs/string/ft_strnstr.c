/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strnstr.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: cpapot <cpapot@student.42lyon.fr >         +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/11/09 13:45:14 by cpapot            #+#    #+#             */
/*   Updated: 2022/11/30 12:05:31 by cpapot           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../../includes/libft.h"

char	*ft_strnstr(const char *haystack, const char *needle, size_t len)
{
	size_t	i;
	size_t	u;

	i = 0;
	if (*needle == 0)
		return ((char *)haystack);
	if (needle[i] == '\0')
		return ((char *)(needle));
	while (i < len && haystack[i])
	{
		u = 0;
		while (haystack[i + u] == needle[u] && haystack[i + u] && i + u < len)
			u++;
		if (needle[u] == '\0')
			return ((char *)&haystack[i]);
		i++;
	}
	return (NULL);
}
