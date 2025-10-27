#				______ _ _
#				|  ____(_) |
#				| |__   _| | ___  ___
#				|  __| | | |/ _ \/ __|
#				| |    | | |  __/\__ \.
#				|_|    |_|_|\___||___/

HEADERS 	=	libft.h get_next_line.h

GNLSRC		=	get_next_line.c get_next_line_utils.c

CHARSRC		=	ft_isalpha.c ft_isdigit.c \
				ft_isalnum.c ft_isascii.c \
				ft_isprint.c ft_tolower.c \
				ft_toupper.c

STRINGSRC	=	ft_strmapi.c ft_striteri.c \
				ft_substr.c ft_strlen.c \
				ft_strlcpy.c ft_strlcat.c \
				ft_strchr.c ft_strrchr.c \
				 ft_strnstr.c \
				ft_atoi.c ft_strncmp.c \
				ft_strdup.c ft_strtrim.c \
				ft_split.c ft_itoa.c \
				ft_strjoin.c ft_atoll.c \
				ft_strcmp.c ft_split_no.c

MEMSRC		=	ft_memset.c ft_bzero.c \
				ft_memcpy.c ft_memmove.c \
				ft_calloc.c ft_memcmp.c \
				ft_memchr.c stock_malloc.c \
				stock_free.c

WRITESRC	=	ft_putstr_fd.c ft_putchar_fd.c \
				ft_putnbr_fd.c ft_putendl_fd.c

LSTSRC		=	ft_lstnew.c ft_lstadd_front.c \
				ft_lstadd_back.c ft_lstsize.c \
				ft_lstlast.c ft_lstdelone.c \
				ft_lstiter.c ft_lstclear.c \
				ft_lstmap.c

INTLSTSRC	=	ft_lstintnew.c ft_lstintadd_front.c \
				ft_lstintadd_back.c ft_lstintsize.c \
				ft_lstintlast.c ft_lstintdelone.c \
				ft_lstintiter.c ft_lstintclear.c \
				ft_lstintmap.c

#					Directories

HEADERSDIR	=	includes/

SRCSDIR		=	srcs/

GNLDIR		=	gnl/

CHARDIR		=	char/

STRINGDIR	=	string/

MEMDIR		=	mem/

WRITEDIR	=	write/

LSTDIR		=	lst/

LSTINTDIR	=	lst_int/

PRINTFFDDIR	=	ft_printf_fd/

PRINTFDIR	=	ft_printf/

#					Full Path

SRCS		=	$(addprefix $(SRCSDIR)$(CHARDIR),$(CHARSRC)) \
				$(addprefix $(SRCSDIR)$(STRINGDIR),$(STRINGSRC)) \
				$(addprefix $(SRCSDIR)$(MEMDIR),$(MEMSRC)) \
				$(addprefix $(SRCSDIR)$(WRITEDIR),$(WRITESRC)) \
				$(addprefix $(SRCSDIR)$(LSTDIR),$(LSTSRC)) \
				$(addprefix $(SRCSDIR)$(LSTINTDIR),$(INTLSTSRC)) \
				$(addprefix $(SRCSDIR)$(GNLDIR),$(GNLSRC)) \


PRINTF		=	$(addprefix $(SRCSDIR),$(PRINTFDIR))

PRINTFFD	=	$(addprefix $(SRCSDIR),$(PRINTFFDDIR))

HEADER		=	$(addprefix $(HEADERSDIR),$(HEADERS))

OBJS		=	$(SRCS:.c=.o)

#		 __      __        _       _     _
#		 \ \    / /       (_)     | |   | |
#		  \ \  / /_ _ _ __ _  __ _| |__ | | ___  ___
#		   \ \/ / _` | '__| |/ _` | '_ \| |/ _ \/ __|
#		    \  / (_| | |  | | (_| | |_) | |  __/\__ \.
#		     \/ \__,_|_|  |_|\__,_|_.__/|_|\___||___/

PRINT_COMPILE = @echo "\033[1;32m⏳ compiling libft\033[1;0m"

RED			=	\033[1;31m
GREEN		=	\033[1;32m
YELLOW		=	\033[1;33m
BLUE		=	\033[1;34m
CYAN		=	\033[1;36m
DEFAULT		=	\033[0m
SUPPR		=	\r\033[2K

AR			=	ar rcs

NAME		=	libft.a

CFLAGS		=	-Wall -Wextra -Werror -g3 -g

CC			=	gcc

RM			=	rm -rf

MKDIR		=	mkdir -p

#				  _____       _
#				 |  __ \     | |
#				 | |__) |   _| | ___  ___
#				 |  _  / | | | |/ _ \/ __|
#				 | | \ \ |_| | |  __/\__ \.
#				 |_|  \_\__,_|_|\___||___/

%.o: %.c ${HEADER}
	@echo -n "${YELLOW}${SUPPR}	⌛ Creating libft's objects : $@"
	@$(CC) -Iincludes ${CFLAGS} -c $< -o $@

all : ${NAME} printf printffd

${NAME}: ${OBJS}
	@${AR} ${NAME} ${OBJS}
	@echo -n "${SUPPR}	${GREEN}LIBFT : 🆗${DEFAULT}\n"

clean:
	@${MAKE} --no-print-directory clean -C ${PRINTF}
	@${MAKE} --no-print-directory clean -C ${PRINTFFD}
	@${RM} ${OBJS}
	@echo "\033[1;31m🗑  libft cleaned\033[1;0m"

fclean:
	@${MAKE} --no-print-directory clean
	@${RM} ${NAME}
	@${MAKE} --no-print-directory fclean -C ${PRINTF}
	@${MAKE} --no-print-directory fclean -C ${PRINTFFD}
	@echo "\033[1;31m🗑  ft_printf cleaned\033[1;0m"
	@echo "\033[1;31m🗑  ft_printf_fd cleaned\033[1;0m"

re:
	@${MAKE} --no-print-directory fclean
	@${MAKE} --no-print-directory all

printf: ${PRINTF}
	@${MAKE} -s -C ${PRINTF}

printffd: ${PRINTFFD}
	@${MAKE} -s -C ${PRINTFFD}

.PHONY : re all clean fclean printf printffd
