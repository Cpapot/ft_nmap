/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   stock_malloc.c                                     :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: cpapot <cpapot@student.42lyon.fr >         +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2023/02/12 19:40:10 by cpapot            #+#    #+#             */
/*   Updated: 2023/04/07 17:11:15 by cpapot           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../../includes/libft.h"

static void	lst_mem_add(t_memlist **lst, t_memlist *new)
{
	t_memlist	*last;

	if (new == NULL || lst == NULL)
		return ;
	last = *lst;
	if (last == NULL)
		*lst = new;
	else
	{
		while (last->next != NULL)
			last = last->next;
		last->next = new;
	}
}

static t_memlist	*lst_mem_new(void *content)
{
	t_memlist	*node;

	node = malloc(sizeof(t_memlist));
	if (node == NULL)
		return (NULL);
	node->content = content;
	node->next = NULL;
	return (node);
}

void	*stock_malloc(size_t size, t_memlist **stock)
{
	void		*result;
	t_memlist	*tmp;

	result = malloc(size);
	if (result == NULL)
		return (NULL);
	if (*stock == NULL)
		*stock = lst_mem_new(result);
	else
	{
		tmp = lst_mem_new(result);
		if (tmp == NULL)
			return (NULL);
		lst_mem_add(stock, tmp);
	}
	return (result);
}
