/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_lstintclear.c                                   :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: cpapot <cpapot@student.42lyon.fr >         +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/11/14 15:16:05 by cpapot            #+#    #+#             */
/*   Updated: 2022/12/09 21:40:37 by cpapot           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../../includes/libft.h"

void	ft_lstintclear(t_int_list **lst)
{
	t_int_list	*node;
	t_int_list	*next_node;

	if (lst == NULL)
		return ;
	node = *lst;
	while (node)
	{
		next_node = node->next;
		free(node);
		node = next_node;
	}
	*lst = NULL;
	return ;
}
