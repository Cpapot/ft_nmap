/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strjoin.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: cpapot <cpapot@student.42lyon.fr >         +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/11/10 19:02:18 by cpapot            #+#    #+#             */
/*   Updated: 2023/03/04 16:01:08 by cpapot           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../../includes/libft.h"

char	*ft_strjoin(char const *s1, char const *s2, t_memlist **stock)
{
	char	*strs;
	int		i;
	int		u;

	i = 0;
	u = 0;
	if (!s1 || !s2)
		return (NULL);
	strs = stock_malloc(sizeof(char)
			* (ft_strlen(s1) + ft_strlen(s2) + 1), stock);
	if (strs == NULL)
		return (NULL);
	while (s1[i] != '\0')
	{
		strs[i] = s1[i];
		i++;
	}
	while (s2[u] != '\0')
	{
		strs[i + u] = s2[u];
		u++;
	}
	strs[i + u] = '\0';
	return (strs);
}
