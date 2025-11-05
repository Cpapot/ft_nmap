/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   parsing.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: coco <coco@student.42.fr>                  +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/11/05 17:23:42 by coco              #+#    #+#             */
/*   Updated: 2025/11/05 18:14:40 by coco             ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "parsing.h"

int checkFlags(char *flags_line)
{
	char **flags = ft_split_no(FLAGS_LIST, ' ');
	
	for (int i = 0; i != FLAG_COUNT; i++)
	{
		if (ft_strcmp(flags_line, flags[i]))
		{
			ft_free_split(flags);
			return i + 1;
		}
	}
	ft_free_split(flags);
	return UNKNOWN_F;
}

//ajouter une fonction de parsing pour chaque flag (parseFile(), parsePorts()......)

// return 0 si le prog doit continuer 1 si on doit fermer
int	parsing(int argc, char **argv /*, t_nmap_data **data*/)
{
	for (int i = 1; i != argc; i++)
	{
		if (isFlags(argv[i]))
		{
			int flagId = checkFlags(argv[i]);
			switch (flagId)
			{
				case UNKNOWN_F:
					printf(UNKNOWN_FLAG, argv[i]);
					return 1;
				default :
					printf("%d\n", flagId);
					break;
			}
		}
		else
		{
			printf(UNKNOWN_PARAM, argv[i]);
			return 1;
		}
	}
	return 1;
}