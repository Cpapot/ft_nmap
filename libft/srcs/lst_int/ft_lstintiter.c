/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_lstintiter.c                                    :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: cpapot <cpapot@student.42lyon.fr >         +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/11/14 15:10:05 by cpapot            #+#    #+#             */
/*   Updated: 2022/12/10 18:31:33 by cpapot           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../../includes/libft.h"

void	ft_lstintiter(t_int_list *lst, int (*f)(int))
{
	if (!lst && !f)
		return ;
	while (lst != NULL)
	{
		f(lst->cont);
		lst = lst->next;
	}
}
