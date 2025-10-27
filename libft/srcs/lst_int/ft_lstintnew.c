/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_lstintnew.c                                     :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: cpapot <cpapot@student.42lyon.fr >         +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/11/12 12:05:01 by cpapot            #+#    #+#             */
/*   Updated: 2023/05/13 14:00:35 by cpapot           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../../includes/libft.h"

t_int_list	*ft_lstintnew(int cont, t_memlist **mem)
{
	t_int_list	*node;

	node = stock_malloc(sizeof(t_list), mem);
	if (node == NULL)
		return (NULL);
	node->cont = cont;
	node->next = NULL;
	return (node);
}
