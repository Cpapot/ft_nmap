/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   network_utils.c                                    :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: cpapot <cpapot@student.42lyon.fr >         +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/11/12 15:18:27 by cpapot            #+#    #+#             */
/*   Updated: 2025/11/12 15:35:57 by cpapot           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

# include "network.h"

char *resolve_host(const char *host)
{
	struct addrinfo hints, *res;
	struct sockaddr_in *addr;
	char *result;

	ft_memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;

	if (getaddrinfo(host, NULL, &hints, &res) != 0)
		return NULL;

	addr = (struct sockaddr_in *)res->ai_addr;
	result = inet_ntoa(addr->sin_addr);
	freeaddrinfo(res);
	return result;
}
