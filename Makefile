NAME = sniffd

OBJ_DIR = ./

SRC_DIR = src/

INC_DIR = include/

SRC = main.c sniffer.c

OBJ = $(addprefix $(OBJ_DIR), $(SRC:.c=.o))

CC = gcc

CC_FLAGS = -Wall -Wextra -Werror

all: $(NAME)

$(NAME): $(OBJ)
	$(CC) -o $(NAME) $(OBJ)

$(OBJ_DIR)%.o: %.c
	$(CC) -c $< -o $@ $(CC_FLAGS) -I $(INC_DIR)

clean:
	/bin/rm -f $(OBJ)

fclean: clean
	/bin/rm -f $(NAME)

re: fclean all

run:
	./$(NAME)

vpath %.c $(SRC_DIR)
