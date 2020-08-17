/*
	binary protection
	mohammad hossein asghari
*/
#define _GNU_SOURCE

#include "enLoader.h"

int main(int argc, char** argv)
{
	if(argc < 2)
	{
		puts("[-] please type arguments:\n\t./enLoader <-e (encrypte) |-d (decrypte) > <program_file>\n");
		exit(0);
	}
	int file_size = get_file_size(argv[2]);
	if(!strcmp(argv[1], "-e"))
	{
		chain_encrypte(argv[2], file_size);
		
	}
	return 0;
	char *program_dec = (char *) calloc(file_size, sizeof(char));
	char *key = (char *) calloc(256, sizeof(char));
	get_decrypte_key(key, argv[2], argv[3]);
	get_decrypte_file(program_dec, argv[1], file_size, key);
	
	int fd = memfd_create("", MFD_CLOEXEC);
	char *program_exec;
	write(fd, program_dec, file_size);
	asprintf(&program_exec, "/proc/self/fd/%i", fd);
	execl(program_exec, "arg1", "arg2", "arg3", NULL);
	puts("[-] error while executing decrypted program");
	return 0;
}
