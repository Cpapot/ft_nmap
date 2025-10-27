/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_printf_fd.h                                     :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: cpapot <cpapot@student.42lyon.fr >         +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/11/21 16:49:21 by cpapot            #+#    #+#             */
/*   Updated: 2023/02/13 19:18:18 by cpapot           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef FT_PRINTF_FD_H
# define FT_PRINTF_FD_H

# include <stdint.h>
# include <unistd.h>
# include <stdarg.h>
# include <stddef.h>
# include <stdlib.h>

int		ft_printf_fd(int fd, const char *format, ...);
size_t	ft_strlen(const char *str);
char	*ft_substr(char const *s, unsigned int start, size_t len);
char	*ft_itoa(int n);
void	ft_bzero(void *s, size_t n);
ssize_t	ft_putnull_len_fd(int fd);
ssize_t	ft_putchar_len_fd(int fd, char c);
ssize_t	ft_putint_len_fd(int fd, int nbr);
ssize_t	ft_putpercent_len_fd(int fd);
ssize_t	ft_putstr_len_fd(int fd, char *str);
ssize_t	ft_putunsint_len_fd(int fd, unsigned int nbr);
ssize_t	ft_puthexamin_len_fd(int fd, unsigned int nbr);
ssize_t	ft_puthexamaj_len_fd(int fd, unsigned int nbr);
ssize_t	ft_puthexavoid_len_fd(int fd, void *arg);
ssize_t	ft_callformat_fd(int fd, char const *format, va_list variadic);

#endif
