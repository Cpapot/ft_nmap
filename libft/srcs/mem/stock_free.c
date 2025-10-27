/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   stock_free.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: cpapot <cpapot@student.42lyon.fr >         +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2023/02/12 19:37:27 by cpapot            #+#    #+#             */
/*   Updated: 2023/02/12 19:39:01 by cpapot           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../../includes/libft.h"

static void	lst_mem_clear(t_memlist **lst)
{
	t_memlist	*node;
	t_memlist	*next_node;

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

void	stock_free(t_memlist **stock)
{
	t_memlist	*tmp;

	tmp = *stock;
	while (tmp)
	{
		free (tmp->content);
		tmp = tmp->next;
	}
	lst_mem_clear(stock);
}
