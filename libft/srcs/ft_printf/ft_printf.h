/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_printf.h                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: cpapot <cpapot@student.42lyon.fr >         +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/11/21 16:49:21 by cpapot            #+#    #+#             */
/*   Updated: 2023/01/18 19:55:54 by cpapot           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef FT_PRINTF_H

# define FT_PRINTF_H

# include <stdint.h>
# include <unistd.h>
# include <stdarg.h>
# include <stddef.h>
# include <stdlib.h>

int		ft_printf(const char *format, ...);
size_t	ft_strlen(const char *str);
char	*ft_substr(char const *s, unsigned int start, size_t len);
char	*ft_itoa(int n);
void	ft_bzero(void *s, size_t n);
ssize_t	ft_putnull_len(void);
ssize_t	ft_putchar_len(char c);
ssize_t	ft_putint_len(int nbr);
ssize_t	ft_putpercent_len(void);
ssize_t	ft_putstr_len(char *str);
ssize_t	ft_putunsint_len(unsigned int nbr);
ssize_t	ft_puthexamin_len(unsigned int nbr);
ssize_t	ft_puthexamaj_len(unsigned int nbr);
ssize_t	ft_puthexavoid_len(void *arg);
ssize_t	ft_callformat(char const *format, va_list variadic);

#endif
