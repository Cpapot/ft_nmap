/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_lstmap.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: cpapot <cpapot@student.42lyon.fr >         +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/11/14 15:54:56 by cpapot            #+#    #+#             */
/*   Updated: 2023/02/13 19:03:19 by cpapot           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../../includes/libft.h"

t_list	*ft_lstmap(t_list *lst, void *(*f)(void *), t_memlist **mem)
{
	t_list	*start;
	t_list	*new;

	if (lst == NULL || f == NULL)
		return (NULL);
	start = ft_lstnew(f(lst->content), mem);
	lst = lst->next;
	while (lst)
	{
		new = ft_lstnew(f(lst->content), mem);
		if (new == NULL)
		{
			ft_lstclear(&start);
			return (NULL);
		}
		ft_lstadd_back(&start, new);
		lst = lst->next;
	}
	return (start);
}
