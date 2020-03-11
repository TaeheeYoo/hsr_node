LIBMNL_CFLAGS = -I/usr/local/include
LIBMNL_LIBS = -L/usr/local/lib -lmnl

CC=${CROSS_COMPILE}gcc

.PHONY:all
	all: hsr_node

hsr_node: hsr_node.c
	        $(CC) -Wextra -Wall -Werror -Wno-unused-parameter hsr_node.c $(LIBMNL_CFLAGS) $(LIBMNL_LIBS) -o hsr_node

.PHONY: clean
	clean:
	        rm -f hsr_node
