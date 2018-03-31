BIN = ACC 
#CC = arm-linux-gcc
CC = gcc
OBJ_DIR = ./obj
CFLAGS  = -O2 -g -c -D_POSIX_C_SOURCE=200809L -D_XOPEN_SOURCE=700 -DDB_SQLITE3
#LDFLAGS = -L/home/naushada/build_root/Pi3B/buildroot-2017.02.1/output/target/usr/lib
#LDFLAGS = -L/home/naushada/mysql-client/arm/v7_cortexA53/mysql-connector-c-6.1.11-src/arm-build/libmysql
LDFLAGS = -L/usr/local/mysql-8.0.3-rc/lib
LIBS    = -lmysqlclient -lrt -lsqlite3 -lpthread

INC = -I../inc -I/usr/local/mysql-8.0.3-rc/include
#INC = -I../inc

SRC = $(shell find . -type f -name '*.c')

#OBJ = $(SRC:.c=.o)
OBJ = $(patsubst %.c, %.o, $(SRC))

#ONLY_OBJ = $(notdir $(OBJ))


all: $(SRC) $(BIN)

$(BIN): $(OBJ)
	@echo $(OBJ)
	$(CC) $(OBJ) $(LDFLAGS) $(LIBS) -o $@

%.o:	%.c
	@echo $<
	$(CC) $(CFLAGS) $(INC) $< -o $@


clean:
	rm -fr *.o
	rm -fr $(BIN)



