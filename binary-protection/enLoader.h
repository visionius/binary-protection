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
#include <memory.h>
#include "sha256.h"
#include "aes.h"


#define _CHUNK_SIZE_ 128

typedef struct
{
    char chunk_bytes[_CHUNK_SIZE_];
} Chunk_codes;


Chunk_codes *chain_encrypt(char *filename, int file_size)
{
    //open file
    FILE *fd = fopen(filename, "rb");
    char *fileContent = (char *) calloc(file_size, sizeof(char));
    fread(fileContent, file_size, 1, fd);
    int chunk_numbers = file_size % _CHUNK_SIZE_ ? (file_size / _CHUNK_SIZE_) + 1 : (file_size / _CHUNK_SIZE_);
    Chunk_codes *chunks = (Chunk_codes *) calloc(chunk_numbers, sizeof(Chunk_codes));
	Chunk_codes *chunks_res = (Chunk_codes *) calloc(chunk_numbers, sizeof(Chunk_codes));
    //initialize chunks
	unsigned long long int offset = 0;
	for(int j = 0; j < chunk_numbers; j++)
	{
		for(int i = 0; i < _CHUNK_SIZE_ && offset < file_size; i++)
		{
			chunks[j].chunk_bytes[i]=fileContent[offset];
			offset++;
		}
	}
	//hash & encrypt
	/*BYTE key[1][32] = {
		{0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4}
	};*/
	BYTE iv[1][16] = {
		{0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f}
	};
	BYTE hashed_chunk[SHA256_BLOCK_SIZE];
	SHA256_CTX ctx;
	int idx;
	BYTE key[1][32];
	memcpy(chunks_res[0].chunk_bytes, chunks[0].chunk_bytes, _CHUNK_SIZE_);
	puts("\n\n");
	printf(chunks_res[0].chunk_bytes);
	puts("\n\n");
	for(int k = 0 ; k < chunk_numbers-1; k++)
	{
		sha256_init(&ctx);
		sha256_update(&ctx, chunks[k].chunk_bytes, strlen(chunks[k].chunk_bytes));
		sha256_final(&ctx, hashed_chunk);
		printf("\nblock [%d]: ", k);
		for(int  i = 0 ; i < SHA256_BLOCK_SIZE ; i++)
		{
			key[0][i] = hashed_chunk[i];
			printf("%x", key[0][i]);
		}
		WORD *key_schedule = (WORD *) calloc(60, sizeof(WORD));
		aes_key_setup(key[0], key_schedule, 256);
		aes_encrypt_cbc(chunks[k+1].chunk_bytes, _CHUNK_SIZE_ , chunks_res[k+1].chunk_bytes, key_schedule, 256, iv[0]);
		free(key_schedule);

	}
	return chunks_res;
}
Chunk_codes *chain_decrypt(char *filename, int file_size)
{
	FILE *fd = fopen(filename, "rb");
    char *fileContent = (char *) calloc(file_size, sizeof(char));
    fread(fileContent, file_size, 1, fd);
    int chunk_numbers = file_size % _CHUNK_SIZE_ ? (file_size / _CHUNK_SIZE_) + 1 : (file_size / _CHUNK_SIZE_);
    Chunk_codes *chunks = (Chunk_codes *) calloc(chunk_numbers, sizeof(Chunk_codes));
	Chunk_codes *chunks_res = (Chunk_codes *) calloc(chunk_numbers, sizeof(Chunk_codes));
    //initialize chunks
	unsigned long long int offset = 0;
	for(int j = 0; j < chunk_numbers; j++)
	{
		for(int i = 0; i < _CHUNK_SIZE_ && offset < file_size; i++)
		{
			chunks[j].chunk_bytes[i]=fileContent[offset];
			offset++;
		}
	}
	BYTE iv[1][16] = {
		{0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f}
	};
	BYTE hashed_chunk[SHA256_BLOCK_SIZE];
	SHA256_CTX ctx;
	int idx;
	BYTE key[1][32];
	memcpy(chunks_res[0].chunk_bytes, chunks[0].chunk_bytes, _CHUNK_SIZE_);
	puts("\n\n");
	printf("%c", fileContent[0]);
	printf("%c", fileContent[1]);
	printf("%c", fileContent[2]);
	printf(chunks_res[0].chunk_bytes);
	puts("\n\n");
	for(int k = 0 ; k < chunk_numbers-1; k++)
	{
		sha256_init(&ctx);
		sha256_update(&ctx, chunks_res[k].chunk_bytes, strlen(chunks_res[k].chunk_bytes));
		sha256_final(&ctx, hashed_chunk);
		printf("\nblock [%d]: ", k);
		for(int  i = 0 ; i < SHA256_BLOCK_SIZE ; i++)
		{
			key[0][i] = hashed_chunk[i];
			printf("%x", key[0][i]);
		}
		WORD *key_schedule = (WORD *) calloc(60, sizeof(WORD));
		aes_key_setup(key[0], key_schedule, 256);
		aes_decrypt_cbc(chunks[k+1].chunk_bytes, _CHUNK_SIZE_ , chunks_res[k+1].chunk_bytes, key_schedule, 256, iv[0]);
		free(key_schedule);
	}
	return chunks_res;
}
void test_chunks(int chunk_numbers, Chunk_codes *chunks, int file_size)
{

	for(int i = 0 ; i < chunk_numbers; i++)
	{
		for(int j = 0 ; j < _CHUNK_SIZE_; j++)
		printf("%x ", (char )chunks[i].chunk_bytes[j]);
	}
	printf("file_Size: %d, number_chunks: %d", file_size, chunk_numbers);

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
