/*
 * Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <err.h>
#include <stdio.h>
#include <string.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* To the the UUID (found the the TA's h-file(s)) */
#include <TEEencrypt_ta.h>


//RSA=================================================
#define RSA_KEY_SIZE 1024
#define RSA_MAX_PLAIN_LEN_1024 86 // (1024/8) - 42 (padding)
#define RSA_CIPHER_LEN_1024 (RSA_KEY_SIZE / 8)

char in_RSA[RSA_MAX_PLAIN_LEN_1024];
char out_RSA[RSA_CIPHER_LEN_1024];
//====================================================

int main(int argc, char* argv[])	// for input file
{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID uuid = TA_TEEencrypt_UUID;
	uint32_t err_origin;
	char plaintext[64] = {0,};
	char ciphertext[64] = {0,};
	int len=64;

	//-------------------------------------------------------------
	//-------------------------------------------------------------

	char enctext[64] = {0, };
	char enckey[64] = {0, };

	//-------------------------------------------------------------
	//-------------------------------------------------------------

	res = TEEC_InitializeContext(NULL, &ctx);
	
	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	
	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);
	
	// 
	op.params[0].tmpref.buffer = plaintext;
	op.params[0].tmpref.size = len;

	op.params[1].value.a = -1;		//

	int key;

if (strcmp(argv[3], "caesar") == 0) {

	if(strcmp(argv[1], "-e") == 0)
	{
		printf("========================Encryption========================\n");

		//FILE *encFile = fopen("encrypted_file.txt", "w+");

		//file read
		FILE *file = fopen(argv[2], "r");
		if(file == NULL)		//if not found
		{		
			printf("no file\n");	
			return 0;
		}

		// 
		fgets(plaintext, sizeof(plaintext), file);
		fclose(file);

		// copy plaintext to buffer
		memcpy(op.params[0].tmpref.buffer, plaintext, len); 

		// start ENC
		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_ENC_VALUE, &op,
				 &err_origin);
		
		// print enc text
		memcpy(ciphertext, op.params[0].tmpref.buffer, len);	// copy buffer to ciphertext
		printf("Encrypted text : %s", ciphertext);

		//memcpy(key, op.params[1].value.a, 1);
		printf("key : %d\n", op.params[1].value.a );

		// make enc file
		FILE *encFile = fopen("encrypted_file.txt", "w+");	// 
		if(encFile == NULL)				//
		{		
			printf("no file\n");	
			return 0;
		}
		fwrite(ciphertext, strlen(ciphertext), 1, encFile);
		fprintf(encFile, "%d", op.params[1].value.a);
		fclose(encFile);

		printf("finsh enc\n");
	}

	else if(strcmp(argv[1], "-d") == 0)
	{
		printf("========================Decryption========================\n");

		// load file
		FILE *encFile = fopen(argv[2], "r");
		if(encFile == NULL)
		{		
			printf("no file\n");	
			return 0;
		}
 
		// 
		fgets(enctext, sizeof(enctext), encFile);
		fgets(enckey, sizeof(enckey), encFile);
		fclose(encFile);

		// load key
		memcpy(op.params[0].tmpref.buffer, enctext, len);
		int key = atoi(enckey);	// char to int 
		
		op.params[1].value.a = key;

		// run dec
		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_DEC_VALUE, &op,
				 &err_origin);

		// print dec text
		memcpy(ciphertext, op.params[0].tmpref.buffer, len);
		printf("Decrypted text : %s", ciphertext);

		//memcpy(key, op.params[1].value.a, 1);
		printf("key : %d\n", key);
	
		// make dec file 
		FILE *decfile = fopen("decrypted_file.txt", "w+");
		if(decfile == NULL)
		{		
			printf("no file\n");	
			return 0;
		}
		fwrite(ciphertext, strlen(ciphertext), 1, decfile);
		fprintf(decfile, "%d", op.params[1].value.a);
		fclose(decfile);

		printf("finsh dec\n");
	}
}//end caesar=====================================

else if(strcmp(argv[3], "RSA") == 0)
	{
		printf("========================RSA========================\n");

		op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 		TEEC_MEMREF_TEMP_OUTPUT,
					 		TEEC_NONE, TEEC_NONE);
	
		op.params[0].tmpref.buffer = in_RSA;			// RSA max arr
		op.params[0].tmpref.size =  RSA_MAX_PLAIN_LEN_1024;
		op.params[1].tmpref.buffer = out_RSA;
		op.params[1].tmpref.size =  RSA_CIPHER_LEN_1024;

		if (!strcmp(argv[1], "-e")){	
	
		// read file
		FILE *file = fopen(argv[2], "r");
		if (file == NULL){
			printf("no file\n");
			return 0;		
		}
		fgets(in_RSA, sizeof(in_RSA), file);
		fclose(file);

		// create RSA key
		res = TEEC_InvokeCommand(&sess, TA_RSA_CMD_GENKEYS, &op, &err_origin);
		
		// ENC file use RSA key
		res = TEEC_InvokeCommand(&sess, TA_RSA_CMD_ENCRYPT,
				 &op, &err_origin);

		
		// print RSA
		memcpy(out_RSA, op.params[1].tmpref.buffer, len);
		printf("RSA Encrypted : %s\n", out_RSA);

		// create RSA file
		FILE *rsa_enc = fopen("rsa_enc.txt", "w+");
		fwrite(out_RSA, strlen(out_RSA), 1, rsa_enc);
		fclose(rsa_enc);
		
		}	
	}
	else
	{
		printf("option error\n");
	}































	TEEC_CloseSession(&sess);
	TEEC_FinalizeContext(&ctx);

	return 0;
}
