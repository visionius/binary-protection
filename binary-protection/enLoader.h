#define _GNU_SOURCE
#include <sys/mman.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pwd.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <linux/elf.h>

#define _CHUNK_SIZE_ 128

typedef struct
{
    char chunk_bytes[_CHUNK_SIZE_];
} Chunk_codes;


void chain_encrypte(char *filename, int file_size)
{
    //open file
    FILE *fd = fopen(filename, "rb");
    char *fileContent = (char *) calloc(file_size, sizeof(char));
    fread(fileContent, file_size, 1, fd);
    int chunk_numbers = file_size % _CHUNK_SIZE_ ? (file_size / _CHUNK_SIZE_) + 1 : (file_size / _CHUNK_SIZE_);
    Chunk_codes *chunks = (Chunk_codes *) calloc (chunk_numbers, sizeof(char));
    //initialize chunks
    init_chunks(fileContent, file_size, chunks, chunk_numbers);
}

void init_chunks(char *fileContent, int file_size, Chunk_codes chunks, int chunk_numbers)
{

}

void get_decrypte_key(char *key, char *rsaKeyFile, char *keyFile)
{
	//128 byte key 256 char
	int rsaPkeyfd = open(rsaKeyFile, O_RDONLY);
	if(!rsaPkeyfd)
	{
		puts("[-] can't find rsa.private key file. use:\n ./enLoader <program_file> <rsa_private> <key_file>\n");
		exit(0);
	}
	int aeskeyfd = open(keyFile, O_RDONLY);
	if(!aeskeyfd)
	{
		puts("[-] can't find key file. use:\n ./enLoader <program_file> <rsa_private> <key_file>\n");
		exit(0);
	}
	
	pid_t keyChild;
	puts("[+] decrypting key file");
	int out_pipe[2];
	int status;
	pipe(out_pipe);
	keyChild = fork();
	if(keyChild == 0)
	{
		dup2(out_pipe[1], STDOUT_FILENO);
		close(out_pipe[1]);
		execl("/usr/bin/openssl", "openssl", "rsautl" ,"-decrypt", "-inkey", rsaKeyFile, "-in", keyFile, NULL);
		puts("[-] error while decrypting key file. make sure openssl is installed.");
		exit(0);
	}
	wait(&status);
	read(out_pipe[0], key, 256);
	puts("[+] key decrypted successfully");
}
void get_decrypte_file(char *program_dec, char *program_enc, int program_size, char *key)
{
	pid_t child;
	int status;
	int out_pipe[2];
	pipe(out_pipe);
	puts("[+] decrypting program");
	child = fork();
	if(child == 0)
	{
		dup2(out_pipe[1], STDOUT_FILENO);
		close(out_pipe[1]);
		execl("/usr/bin/openssl", "openssl", "enc", "-d", "-aes-256-cbc", "-in", program_enc, "-k", key, NULL);			
		puts("[-] error while decrypting program file. make sure openssl is installed.");
		exit(0);
	}
	wait(&status);
	read(out_pipe[0], program_dec, program_size);
	puts("[+] program decrypted successfully");
}
int get_file_size(char *file_name)
{
	int file_size = 0;
	FILE * file = fopen(file_name, "rb");
	if(!file)
	{
		puts("[-] can't find prgram encrypted file\n\t./enLoader <program_file> <rsa_private> <key_file>\n");
		exit(0);
	}
	fseek(file, 0L, SEEK_END);
	file_size = ftell(file);
	fclose(file);
	return file_size;
}
