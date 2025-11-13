/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   parsing.h                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: cpapot <cpapot@student.42lyon.fr >         +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/11/05 17:25:27 by coco              #+#    #+#             */
/*   Updated: 2025/11/13 15:04:35 by cpapot           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef PARSING_H
# define PARSING_H

# include "nmap.h"

# define FLAGS_LIST "--help --ports --ip --file --speedup --scan"
# define FLAG_COUNT 6
# define SCAN_LIST "SYN NULL FIN XMAS ACK UDP"
# define SCAN_COUNT 6

# define HELP_FLAG "Help Screen\nft_nmap [OPTIONS]\n--help Print this help screen\n\
--ports ports to scan (eg: 1-10 or 1,2,3 or 1,5-15)\n--ip ip addresses to scan in dot format\n\
--file File name containing IP addresses to scan,\n--speedup [250 max] number of parallel threads to use\n\
--scan SYN/NULL/FIN/XMAS/ACK/UDP\n"

/*				parser error				*/
# define UNKNOWN_FLAG "Unknown flag: %s\n"
# define UNKNOWN_PARAM "Unknown parameter: %s\n"
# define MISSING_ARG "Missing argument for flag: %s\n"

# define INVALID_PORT "Invalid port parameter: %s\n"
# define MAX_PORT_REACHED "Max ports reached (1024), the remaining ports will not be scanned.\n"

# define UNKNOWN_HOST "Unknown host: %s\n"

# define CANT_OPEN_FILE "Error opening file: %s\n"

# define NO_IP "No IP specified, closing nmap\n"

# define INVALID_SPEEDUP_PARAMETER "Invalid threads count parameter: %s\n"
# define INVALID_THREAD_COUNT "The number of parallel threads must be between 1 and 255\n"

# define UNKNOWN_SCAN "The specified scan does not exist: %s\n"

bool	is_flags(char *str);
bool	is_in_string(char a, char *str);
bool	is_all_numbers(char *str);


enum	e_parsing_flags {
	UNKNOWN_F = 0,
	HELP_F,
	PORTS_F,
	IP_F,
	FILE_F,
	SPEEDUP_F,
	SCAN_F
};

enum	e_parsing_return {
	SUCCES = 0,
};


#endif
