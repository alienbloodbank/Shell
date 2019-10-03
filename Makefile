CC = gcc
CFLAGS = -g -c -Wall -Werror -Wextra

all: proc_parse shell

proc_parse: proc_parse.o
	$(CC) proc_parse.o -o proc_parse

shell: shell.o job_helper.o
	$(CC) shell.o job_helper.o -o shell
	 
object_files: proc_parse.c shell.c job_helper.c
	$(CC) $(CFLAGS) proc_parse.c shell.c job_helper.c

assemblies: proc_parse.c shell.c
	$(CC) -S proc_parse.c shell.c
	
clean:
	rm -rf proc_parse shell *.o *.s
