/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_split.c                                         :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mgagne <mgagne@student.42lyon.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/08/21 13:42:03 by cpapot            #+#    #+#             */
/*   Updated: 2023/06/05 11:38:43 by mgagne           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../../includes/libft.h"

int	is_sep(char s, char *charset)
{
	int	i;

	i = 0;
	while (charset[i] != '\0')
	{
		if (charset[i] == s)
			return (1);
		i++;
	}
	return (0);
}

int	len_word(char *str, char *charset, int u)
{
	int		i;
	int		y;

	i = 0;
	y = 0;
	while (is_sep(str[i], charset) == 1)
		i++;
	while (str[i] != '\0')
	{
		if (!(is_sep(str[i], charset)) && y == u)
			break ;
		else if (is_sep(str[i], charset) && !(is_sep(str[i + 1], charset)))
			y++;
		i++;
	}
	y = 0;
	while (str[i + y] != '\0' && (!is_sep(str[i + y], charset)))
		y++;
	return (y + 1);
}

int	count_word(char *str, char *charset)
{
	int	i;
	int	count;

	i = 0;
	count = 0;
	if (is_sep(str[0], charset) == 1)
		count--;
	while (str[i] != '\0')
	{
		if (is_sep(str[i], charset) && (!(is_sep(str[i + 1], charset))
				&& str[i + 1] != '\0'))
			count++;
		i++;
	}
	return (count + 1);
}

void	cpy_word(char *str, char *charset, int n, char *result)
{
	int		i;
	int		count;
	int		y;

	i = 0;
	count = 0;
	y = 0;
	if (is_sep(str[0], charset) == 1)
		y--;
	while (str[i] != '\0')
	{
		if (is_sep(str[i], charset) && !(is_sep(str[i + 1], charset)))
			y++;
		if (y > n)
			break ;
		if (!(is_sep(str[i], charset)) && y == n)
		{
			result[count] = str[i];
			count++;
		}
		i++;
	}
	result[count] = '\0';
}

char	**ft_split(char *str, char *charset, t_memlist **stock)
{
	char	**result;
	int		word_count;
	int		i;
	int		len;

	i = 0;
	if (str[0] == '\0' || charset[0] == '\0')
		return (NULL);
	word_count = count_word(str, charset);
	result = stock_malloc(sizeof(char *) * (word_count + 1), stock);
	if (result == NULL)
		return (NULL);
	while (i < word_count)
	{
		len = len_word(str, charset, i);
		result[i] = stock_malloc(sizeof(char) * len, stock);
		if (result[i] == NULL)
			return (NULL);
		cpy_word(str, charset, i, result[i]);
		i++;
	}
	result[i] = NULL;
	return (result);
}
