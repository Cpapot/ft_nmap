/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   parsing_utils.c                                    :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: coco <coco@student.42.fr>                  +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/11/05 17:28:28 by coco              #+#    #+#             */
/*   Updated: 2025/11/05 17:35:22 by coco             ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "parsing.h"

/**
 * @brief Determines if a string represents a command-line flag
 * @param str String to check
 * @return true if string starts with '--' and has at least 3 characters, false otherwise
 */
bool	isFlags(char *str)
{
	if (str != NULL)
	{
		if (str[0] == '-' && str[1] == '-' && ft_strlen(str) >= 3)
			return true;
	}
	return false;
}

/**
 * @brief Checks if a character exists within a string
 * @param a Character to search for
 * @param str String to search within
 * @return true if character is found, false otherwise
 */
bool	isInString(char a, char *str)
{
	for (int i = 0; str[i]; i++)
	{
		if (str[i] == a)
			return true;
	}
	return false;
}
