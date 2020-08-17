/*
	binary protection
	mohammad hossein asghari
*/
#define _GNU_SOURCE

#include "enLoader.h"

void write_file(Chunk_codes *chunks, int file_size, FILE *file)
{
	int chunk_numbers = file_size % _CHUNK_SIZE_ ? (file_size / _CHUNK_SIZE_) + 1 : (file_size / _CHUNK_SIZE_);
	char *fileContent = (char *) calloc(file_size, sizeof(char));
    
	unsigned long long int offset = 0;
	for(int j = 0; j < chunk_numbers; j++)
	{
		for(int i = 0; i < _CHUNK_SIZE_ && offset < file_size; i++)
		{
			fileContent[offset] = chunks[j].chunk_bytes[i];
			offset++;
		}
	}
	fwrite(fileContent, file_size, 1, file);
}
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
		Chunk_codes *result = chain_encrypt(argv[2], file_size);
		FILE *file_enc = fopen("encrypted_file", "wb");
		write_file(result, file_size, file_enc);
		fclose(file_enc);
	}
	else if(!strcmp(argv[1], "-d"))
	{
		Chunk_codes *result = chain_decrypt(argv[2], file_size);
		FILE *file_dec = fopen("decrypted_file", "wb");
		write_file(result, file_size, file_dec);
		fclose(file_dec);
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
