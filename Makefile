SRC_P:=./src/

CC:=gcc
CFLAGS:= -I ./include/
CFLAGS+= -Wall

SRC:= 	$(SRC_P)ARP_Sniffer.c 	\
	  	$(SRC_P)main.c			\
		$(SRC_P)ARP_Packet.c	\
		$(SRC_P)ARP_Spoofer.c   \
		$(SRC_P)ARP_Utils.c 	\


OBJ:= $(SRC:.c=.o)

NAME:=main

all: $(NAME)

$(NAME): $(OBJ)
	$(CC) $(OBJ) -o $(NAME) 

clean: 
	rm -f $(OBJ)
