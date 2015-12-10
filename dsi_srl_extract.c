// Copyright 2010  booto 
// Licensed under the terms of the GNU GPL, version 2
// http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt
#include <stdint.h>
#include <stdio.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>

#include "dsi.h"
#include "f_xy.h"
#include "ec.h"
#include "sha1.h"
#include "minIni.h"

#define WIN32 1
#ifdef WIN32

uint32_t le32toh(uint32_t in)
{
	return in;
}

uint16_t le16toh(uint16_t in)
{
	return in;
}
#endif

typedef struct tna4_t
{
	uint32_t magic;
	uint16_t group_id;
	uint16_t version;
	uint8_t mac[8];
	uint8_t hwinfo_n[0x10];
	uint32_t titleid_2;
	uint32_t titleid_1;
	int32_t tmd_elength;
	int32_t content_elength[8];
	int32_t savedata_elength;
	int32_t bannersav_elength;
	uint32_t content_id[8];
	uint32_t savedata_length;
	uint8_t reserved[0x3c];
} tna4_t;

typedef uint8_t sha1_hash[0x14];

typedef struct ecc_point_t
{
	uint8_t r[0x1e];
	uint8_t s[0x1e];
}  ecc_point_t;

typedef struct ecc_cert_t
{
	struct {
		uint32_t type;
		ecc_point_t val;
		uint8_t padding[0x40];
	} sig;
	char issuer[0x40];
	uint32_t key_type;
	char key_id[0x40];
	uint32_t unk;
	ecc_point_t pubkey;
	uint8_t padding2[0x3c];
}  ecc_cert_t;

typedef struct footer_t
{
	sha1_hash banner_hash;
	sha1_hash tna4_hash;
	sha1_hash tmd_hash;
	sha1_hash content_hash[8];
	sha1_hash savedata_hash;
	sha1_hash bannersav_hash;
	ecc_point_t sig;
	ecc_cert_t ap;
	ecc_cert_t tw;
} footer_t;

//#define CI_TMD 0
#define CI_CONTENT_FIRST 0
#define CI_CONTENT_LAST 7
#define CI_CONTENT_COUNT 8
//#define CI_SAVEDATA 9
//#define CI_BANNERSAV 10

#define EOFF_BANNER 0
#define ESIZE_BANNER 0x4020
#define EOFF_TNA4 (EOFF_BANNER+ESIZE_BANNER)
#define ESIZE_TNA4 0xd4
#define EOFF_FOOTER (EOFF_TNA4 + ESIZE_TNA4)
#define ESIZE_FOOTER 0x460
#define EOFF_TMD (EOFF_FOOTER + ESIZE_FOOTER)
#define ESIZE_BANNERSAV 0x4020
#define SIZE_BANNERSAV 0x4000

uint8_t buffer[0x20020];



int decrypt_to_buffer(uint8_t *key, uint8_t *src, uint8_t *dst, uint32_t enc_size, uint32_t *dec_size)
{
	uint32_t bytes_to_dec = 0;
	uint32_t total_dec_bytes = 0;

	dsi_es_context dec;
	dsi_es_init(&dec, key);
	while(enc_size > 0)
	{
		bytes_to_dec = 0x20000;
		if(bytes_to_dec > enc_size - 0x20)
		{
			bytes_to_dec = enc_size - 0x20;
		}
		if(dec_size)
		{
			if(total_dec_bytes + bytes_to_dec > *dec_size)
			{
				return -2;
			}
		}
		memcpy(buffer, src, bytes_to_dec + 0x20);

		if(dsi_es_decrypt(&dec, buffer, buffer + bytes_to_dec, bytes_to_dec) != 0)
		{
			printf("total_dec_bytes: 0x%08x, bytes_to_dec: 0x%08x\n",
				total_dec_bytes, bytes_to_dec);
			return -3;
		}

		memcpy(dst, buffer, bytes_to_dec);

		total_dec_bytes += bytes_to_dec;
		src += bytes_to_dec + 0x20;
		dst += bytes_to_dec;
		enc_size -= bytes_to_dec + 0x20;
	}

	if(dec_size)
	{
		*dec_size = total_dec_bytes;
	}

	return 0;
}

int save_section(const char *filebase, const char *extension, uint8_t *buffer, int len)
{
	char filename[512];
	FILE *out;
	if(filebase != NULL)
	{
		sprintf(filename, "%s.%s", filebase, extension);
		out = fopen(filename, "wb");
	}
	else
	{
		out = fopen(extension, "wb");
	}
	if(out == NULL)
	{
		return -1;
	}
	fwrite(buffer, len, 1, out);
		
	fclose(out);

	return 0;

}


uint32_t tna4_magic = 0x544e4134;


uint8_t tna4_buffer[0xb4];
uint8_t footer_buffer[0x440];
uint8_t banner_buffer[0x4000];
sha1_hash temp_hash;


unsigned char tadsrl_keyX[16] = {0x4a, 0x00, 0x00, 0x4e, 0x4e, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
unsigned char tadsrl_keyY[16] = {0xcc, 0xfc, 0xa7, 0x03, 0x20, 0x61, 0xbe, 0x84, 0xd3, 0xeb, 0xa4, 0x26, 0xb8, 0x6d, 0xbe, 0xc2};
unsigned char sd_key[16] = {0x3d, 0xa3, 0xea, 0x33, 0x4c, 0x86, 0xa6, 0xb0, 0x2a, 0xae, 0xdb, 0x51, 0x16, 0xea, 0x92, 0x62};
char modcrypt_shared_key[8] = {'N','i','n','t','e','n','d','o'};

unsigned char block[0x10];

void decrypt_modcrypt_area(dsi_context* ctx, unsigned char *buffer, unsigned int size)
{
	uint32_t len = size / 0x10;
	while(len>0)
	{
		memset(block, 0, 0x10);
		dsi_crypt_ctr_block(ctx, buffer, block);
		memcpy(buffer, block, 0x10);
		buffer+=0x10;
		len--;
	}
}

int decryptsrl(unsigned char *srl)
{
	unsigned char *keyX_ptr = NULL, *keyY_ptr = NULL;
	uint32_t offset, size;
	int verbose=0;
	unsigned char *header, *buffer;
	unsigned char key_x[16];
	unsigned char key_y[16];
	unsigned char key[16];
	dsi_context ctx;

	header = srl;

	memcpy(key_x, modcrypt_shared_key, 8);

	memcpy(&key_x[8], &header[0x0c], 4);
	key_x[12 + 0] = header[0x0c + 3];
	key_x[12 + 1] = header[0x0c + 2];
	key_x[12 + 2] = header[0x0c + 1];
	key_x[12 + 3] = header[0x0c + 0];
	memcpy(key_y, &header[0x350], 16);
	
	if((header[0x1c] & 4) || (header[0x1bf] & 0x80))
	{
		if(verbose)printf("Crypting dev modcrypt.\n");
	}
	else
	{
		if(verbose)printf("Crypting retail modcrypt.\n");
		keyX_ptr = key_x;
		keyY_ptr = key_y;
	}
	memcpy(key, header, 16);

	if(verbose)printf("Crypting...\n");
	if(keyX_ptr)
	{
		F_XY((uint32_t*)key, (uint32_t*)key_x, (uint32_t*)key_y);
	}
	dsi_set_key(&ctx, key);

	
	memcpy(&offset, &header[0x220], 4);
	memcpy(&size, &header[0x224], 4);
	dsi_set_ctr(&ctx, &header[0x300]);

	if(offset!=0)
	{
		if(verbose)printf("Modcrypt area 0: offset %x size %x\n", offset, size);
		buffer = srl + offset;
		decrypt_modcrypt_area(&ctx, buffer, size);
	}
	else
	{
		if(verbose)printf("Modcrypt area 0 is unused.\n");
	}


	memcpy(&offset, &header[0x228], 4);
	memcpy(&size, &header[0x22c], 4);
	dsi_set_ctr(&ctx, &header[0x314]);

	if(offset!=0)
	{
		if(verbose)printf("Modcrypt area 1: offset %x size %x\n", offset, size);
		buffer = srl + offset;
		decrypt_modcrypt_area(&ctx, buffer, size);
	}
	else
	{
		if(verbose)printf("Modcrypt area 1 is unused.\n");
	}

	if(verbose)printf("Done.\n");
	return 0;
}


int get_contentkey(uint8_t *contentkey, footer_t *footer, char *conidstr)
{
	int i, coni;
	unsigned int tmp;
	unsigned char conid[8];
	unsigned long *conid_words = (unsigned long*)conid;

	unsigned char keyX[16];
	unsigned char keyY[16];
	uint32_t *keyX_words = (uint32_t *)keyX;

	memset(keyX, 0, 16);
	memset(keyY, 0, 16);

	/*if(get_key("tadsrl_keyY", keyY, 16)<0)
	{
		printf("skipping content crypto since opening tadsrl_keyY failed.\n");
		return 1;
	}*/

	if(conidstr==NULL)conidstr = (char*)&footer->tw.key_id[0xb];
	memset(conid, 0, 8);
	i = 0;
	for(coni=7; coni>=0; coni--)
	{
		sscanf(&conidstr[i], "%02x", &tmp);
		conid[coni] = (unsigned char)tmp;
		i+=2;
	}

	memcpy(keyX, tadsrl_keyX, 16);
	memcpy(keyY, tadsrl_keyY, 16);
	keyX_words[2] = conid_words[1] ^ 0xC80C4B72;
	keyX_words[3] = conid_words[0];

	F_XY((uint32_t*)contentkey, keyX_words, (uint32_t*)keyY);

	return 0;
}

int main(int argc, char *argv[])
{
	FILE *fp;
	uint8_t *mapped_file;
	int rv;
	int i;
	int nocontent=0; 
	int nomodcrypt=0;
	
	int argi;
	char str[256];
	char gamestr[256];
	char *conid=NULL;
	char *basename=NULL;
	unsigned long filesize;
	tna4_t *tna4;
	footer_t *footer;
	int32_t offset_to_savedata;
	uint8_t contentkey[0x10];
	int conkey_generated = 0;
	uint32_t tmd_length;
	uint8_t *tmd_buffer;
	uint32_t old_tmd_length;
	uint32_t content_length;
	uint8_t *content_buffer;
	uint32_t old_content_length;
	uint32_t savedata_length;
	uint8_t *savedata_buffer;
	uint32_t old_savedata_length;
	uint8_t *bannersav_buffer;
	uint32_t bannersav_length;
	int save_srl_only = 1;

	nomodcrypt=ini_getl("Main","no_mod_crypt",0,"dsi_srl_extract.ini");
	ini_putl("Main","no_mod_crypt",nomodcrypt,"dsi_srl_extract.ini");

	printf("%s for dsi by booto\n", argv[0]);
	if(argc < 2)
	{
		printf("usage: %s <options> sd_save.bin\n"
			"    files will be created by appending extensions to base_for_output\n"
			"    e.g. if base_for_output is 'test' the banner will be in 'test.banner'\n", argv[0]);
		printf( "    options:\n--nocontent don't crypt content\n");
		printf( "--nomodcrypt - Don't decrypt modcrypted sections in srl\n");
		printf( "--conid=[16 hex character console ID]\n\tDecrypt content with specified console ID, instead of the one in the bin.\n");
		printf( "--basename=[base output name]\n\tOutput all the other content files besides the srl\n");
		return 1;
	}

	for(argi=1; argi<argc; argi++)
	{
		if(strncmp(argv[argi], "--nocontent", 11)==0){nocontent = 1; nomodcrypt = 1; continue;}
		if(strncmp(argv[argi], "--nomodcrypt", 11)==0){nomodcrypt = 1; continue; }
		if(strncmp(argv[argi], "--conid=", 8)==0){conid = &argv[argi][8]; continue; }
		if(strncmp(argv[argi], "--basename=", 11)==0) { basename = &argv[argi][11]; save_srl_only = 0; continue; }
	
		fp = fopen(argv[argi],"rb");
		if(fp==NULL)
		{
			printf("Error opening %s\n",argv[argi]);
			continue;
		}
		fseek(fp,0,SEEK_END);
		filesize = ftell(fp);
		fseek(fp,0,SEEK_SET);
		mapped_file = (uint8_t*)malloc(filesize);
		if(mapped_file == NULL)
		{
			printf("Error allocating memory for file %s\n",argv[argi]);
			fclose(fp);
			continue;
		}
		fread(mapped_file,1,filesize,fp);
		fclose(fp);

	

	
	
		printf("decrypting tna4\n");
	
		rv = decrypt_to_buffer(sd_key, mapped_file+EOFF_TNA4, tna4_buffer,
				ESIZE_TNA4, NULL); 
		if(rv < 0)
		{
			printf("error decrypting tna4: %d\n", rv);
			continue;
		}

		tna4 = (tna4_t*)tna4_buffer;
		if(tna4_magic != le32toh(tna4->magic))
		{
			printf("error: magic is incorrect\n");
			continue;
		}



		printf("tna4:\n");
		printf("magic:    %08x\n", le32toh(tna4->magic));
		printf("group_id: %04hx\n", le16toh(tna4->group_id));
		printf("version:  %04hx\n", le16toh(tna4->version));
		printf("mac:      %02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx\n",
			tna4->mac[5], tna4->mac[4], tna4->mac[3], tna4->mac[2],
			tna4->mac[1], tna4->mac[0]);
		printf("titleid:  %08x-%08x\n", le32toh(tna4->titleid_1),
			le32toh(tna4->titleid_2));
		printf("contents:\n");
		if(le32toh(tna4->tmd_elength) != 0)
		{
			printf(" tmd: 0x%08x ebytes\n",
				le32toh(tna4->tmd_elength));
		}
		for(i=0; i<CI_CONTENT_COUNT; i++)
		{
			if(le32toh(tna4->content_elength[i]) != 0)
			{
				printf(" content(index:0x%02hhx, id:0x%08x): 0x%08x ebytes\n",
					i,
					le32toh(tna4->content_id[i]),
					le32toh(tna4->content_elength[i]));
			}
		}
		if(le32toh(tna4->savedata_elength) != 0)
		{
			printf(" savedata: 0x%08x ebytes [0x%08x bytes]\n",
				le32toh(tna4->savedata_elength),
				le32toh(tna4->savedata_length));
		}
		if(le32toh(tna4->bannersav_elength) != 0)
		{
			printf(" bannersav: 0x%08x ebytes\n",
				le32toh(tna4->bannersav_elength));
		}

		printf("decrypting footer\n");
	
		rv = decrypt_to_buffer(sd_key, mapped_file+EOFF_FOOTER, footer_buffer,
				ESIZE_FOOTER, NULL); 
		if(rv < 0)
		{
			printf("error decrypting footer: %d\n", rv);

			continue;
		}

		footer = (footer_t*)footer_buffer;
		if(!save_srl_only)
		{
			printf("saving footer\n");
			rv = save_section(basename, "footer", footer_buffer, sizeof(footer_buffer));
			if(rv < 0)
			{
				printf("error saving footer: %d\n", rv);
			}
		}
	
		printf("checking footer signature... ");
		fflush(stdout);
		SHA1(footer_buffer, sizeof(footer_t)-sizeof(ecc_cert_t)-sizeof(ecc_cert_t)-sizeof(ecc_point_t), temp_hash);
		rv = check_ecdsa(footer->ap.pubkey.r, footer->sig.r, footer->sig.s, temp_hash);
		if(rv == 1)
		{
			printf("GOOD!\n");
		}
		else
		{
			printf("BAD!\n");
		}

		printf("checking ap signature... ");
		fflush(stdout);
		SHA1((uint8_t*)footer->ap.issuer, sizeof(ecc_cert_t)-sizeof(footer->ap.sig), temp_hash);

		rv = check_ecdsa(footer->tw.pubkey.r, footer->ap.sig.val.r, footer->ap.sig.val.s, temp_hash);
		if(rv == 1)
		{
			printf("GOOD!\n");
		}
		else
		{
			printf("BAD!\n");
		}

		printf("checking tna4 sha1... ");
		SHA1(tna4_buffer, sizeof(tna4_buffer), temp_hash);

		if(memcmp(temp_hash, footer->tna4_hash, sizeof(sha1_hash))==0)
		{
			printf("GOOD!\n");
			if(!save_srl_only)
			{
				printf("saving tna4\n");
				rv = save_section(basename, "tna4", tna4_buffer, sizeof(tna4_buffer));
				if(rv < 0)
				{
					printf("error saving tna4: %d\n", rv);
				}
			}
		}
		else
		{
			printf("BAD!\n");
			for(i=0;i<20;i++)
				printf("%.2X",temp_hash[i]);
			printf("\n");
			for(i=0;i<20;i++)
				printf("%.2X",footer->tna4_hash[i]);
			printf("\n");
		}



		if(!save_srl_only)
		{
			printf("decrypting banner\n");
	
			rv = decrypt_to_buffer(sd_key, mapped_file+EOFF_BANNER, banner_buffer,
					ESIZE_BANNER, NULL); 
			if(rv < 0)
			{
				printf("error decrypting banner: %d\n", rv);
				continue;
			}


			printf("checking banner sha1... ");
			SHA1(banner_buffer, sizeof(banner_buffer), temp_hash);
			if(memcmp(temp_hash, footer->banner_hash, sizeof(sha1_hash))==0)
			{
				printf("GOOD!\n");
				printf("saving banner\n");
				rv = save_section(basename, "banner", banner_buffer, sizeof(banner_buffer));
				if(rv < 0)
				{
					printf("error saving banner: %d\n", rv);
				}
			}
			else
			{
				printf("BAD!\n");
			}
		}
		offset_to_savedata = EOFF_TMD;
		if(nocontent==0)conkey_generated = get_contentkey(contentkey, footer, conid);
		if(nocontent)conkey_generated = 1;
	
		if(conkey_generated==0)
		{
			printf("decrypting tmd\n");
			memset(str, 0, 256);
			sprintf(str,"tmd");
			tmd_length = le32toh(tna4->tmd_elength);
			tmd_buffer = (uint8_t*)malloc(tmd_length);
		
			if (tmd_buffer == NULL)
			{
				printf("error allocating buffer for tmd\n");
				continue;
			}
		
			old_tmd_length = ((tmd_length / 0x20020) * 0x20000);
			if(tmd_length % 0x20020) old_tmd_length += (tmd_length % 0x20020) - 0x20;
		
			rv = decrypt_to_buffer(contentkey, mapped_file + offset_to_savedata,
				tmd_buffer, tmd_length,
				&tmd_length);
			if(rv < 0)
			{
				printf("error decrypting tmd: %d\n", rv);
				continue;
			}
		
			if(tmd_length != old_tmd_length)
			{
				printf("tmd length discrepency: 0x%08x != 0x%08x\n",
					tmd_length,
					old_tmd_length);
				continue;
			}

			printf("checking tmd sha1... ");
			SHA1(tmd_buffer, tmd_length, temp_hash);
			if(memcmp(temp_hash, footer->tmd_hash, sizeof(sha1_hash))==0)
			{
				printf("GOOD!\n");
				if(!save_srl_only)
				{
					rv = save_section(basename, str, tmd_buffer, tmd_length);
					if(rv < 0)
					{
						printf("error saving tmd: %d\n", rv);
					}
				}
			}
			else
			{
				printf("BAD!\n");
			}
			free(tmd_buffer);
		}
		offset_to_savedata += le32toh(tna4->tmd_elength);

		for(i=0; i<CI_CONTENT_COUNT; i++)
		{
			if(save_srl_only && (i>0)) break;
			if(conkey_generated==0)
			{
				if(le32toh(tna4->content_elength[i])==0)continue;

				printf("decrypting content %x\n", i);
				memset(str, 0, 256);
				if(i==0)
				{
					sprintf(str, "srl");
				}
				else
				{
					sprintf(str, "%02x", i);
				}

				content_length = le32toh(tna4->content_elength[i]);
				content_buffer = (uint8_t*)malloc(content_length);

				if(content_buffer == NULL)
				{
					printf("error allocating buffer for content\n");
					break;
				}

	
				old_content_length = ((content_length / 0x20020) * 0x20000);
				if(content_length % 0x20020)old_content_length += (content_length % 0x20020) - 0x20;

				rv = decrypt_to_buffer(contentkey, mapped_file + offset_to_savedata,
					content_buffer, content_length,
					&content_length); 
				if(rv < 0)
				{
					printf("error decrypting content: %d\n", rv);
					break;
				}
	
				if(content_length != old_content_length)
				{
					printf("content length discrepency: 0x%08x != 0x%08x\n",
						content_length,
						old_content_length);
					break;
				}

				printf("checking content sha1... ");
				SHA1(content_buffer, content_length, temp_hash);
				if(memcmp(temp_hash, footer->content_hash[i], sizeof(sha1_hash))==0)
				{
					printf("GOOD!\n");
					if(i==0)
					{
						uint32_t icondata = content_buffer[0x68] | (content_buffer[0x69] << 8) | (content_buffer[0x6A] << 16) | (content_buffer[0x6B] << 24);
						int strpointer = 0;
						icondata += 0x340;
						printf("DSiWare Title: ");
						while(content_buffer[icondata]!=0)
						{
							if(content_buffer[icondata+1]!=0)
							{
								icondata+=2;
								continue;
							}
							printf("%c",content_buffer[icondata]);
							str[strpointer]=content_buffer[icondata];
							switch (str[strpointer])
							{
								case ':':
								case '/':
								case '\\':
								case '?':
								case '<':
								case '>':
								case '|':
								case '*':
								case 0xA:
									str[strpointer]='-';
									break;
								case ' ':
									str[strpointer]='_';
									break;
							
								default:
									break;
							}
							if((str[strpointer]>=0x20)&&(str[strpointer]<=0x7E))
								strpointer++;
							icondata += 2;
						}
						str[strpointer++]='.';
						str[strpointer++]='n';
						str[strpointer++]='d';
						str[strpointer++]='s';
						printf("\n");
						if(nomodcrypt==0)
						{
							printf("decrypting modcrypt sections...\n");
							decryptsrl(content_buffer);
							printf("modcrypt decrypt done.\n");
						}
						rv = save_section(NULL, str, content_buffer, content_length);
						if(rv < 0)
						{
							printf("error saving content: %d\n", rv);
						}
						memcpy(gamestr,str,256);
					}
					else
					{
						if(!save_srl_only)
						{
							rv = save_section(basename, str, content_buffer, content_length);
							if(rv < 0)
							{
								printf("error saving content: %d\n", rv);
							}
						}
					}
				}
				else
				{
					printf("BAD!\n");
				}
			
				free(content_buffer);
			}

			offset_to_savedata += le32toh(tna4->content_elength[i]);
		}
		if(i<CI_CONTENT_COUNT)
			continue;

		if(le32toh(tna4->savedata_elength) != 0)
		{
			printf("decrypting savedata\n");

			savedata_length = le32toh(tna4->savedata_length);
			savedata_buffer = malloc(savedata_length);

			if(savedata_buffer == NULL)
			{
				printf("error allocating buffer for savedata\n");
				continue;
			}

	
			old_savedata_length = savedata_length;
			rv = decrypt_to_buffer(sd_key, mapped_file + offset_to_savedata,
				savedata_buffer, le32toh(tna4->savedata_elength),
				&savedata_length); 
			if(rv < 0)
			{
				printf("error decrypting savedata: %d\n", rv);
				continue;
			}
	
			if(savedata_length != old_savedata_length)
			{
				printf("savedata length discrepency: 0x%08x != 0x%08x\n",
					savedata_length,
					old_savedata_length);
				continue;
			}

			printf("checking savedata sha1... ");
			SHA1(savedata_buffer, savedata_length, temp_hash);
			if(memcmp(temp_hash, footer->savedata_hash, sizeof(sha1_hash))==0)
			{
				printf("GOOD!\n");

				if(!save_srl_only)
				{
					rv = save_section(basename, "savedata", savedata_buffer, savedata_length);
					if(rv < 0)
					{
						printf("error saving savedata: %d\n", rv);
					}
				}
			}
			else
			{
				printf("BAD!\n");
			}
			free(savedata_buffer);
		}
		if(le32toh(tna4->bannersav_elength) == ESIZE_BANNERSAV)
		{
			printf("decrypting bannersav\n");

			bannersav_buffer = (uint8_t*)malloc(SIZE_BANNERSAV);

			if(bannersav_buffer == NULL)
			{
				printf("error allocating buffer for bannersav\n");
				continue;
			}

	
			bannersav_length = SIZE_BANNERSAV;
			rv = decrypt_to_buffer(sd_key, mapped_file + offset_to_savedata + le32toh(tna4->savedata_elength),
				bannersav_buffer, le32toh(tna4->bannersav_elength),
				&bannersav_length); 
			if(rv < 0)
			{
				printf("error decrypting bannersav: %d\n", rv);
				continue;
			}
	
			printf("checking bannersav sha1... ");
			SHA1(bannersav_buffer, bannersav_length, temp_hash);
			if(memcmp(temp_hash, footer->bannersav_hash, sizeof(sha1_hash))==0)
			{
				printf("GOOD!\n");
				if(!save_srl_only)
				{
					rv = save_section(basename, "bannersav", bannersav_buffer, bannersav_length);
					if(rv < 0)
					{
						printf("error saving bannersav: %d\n", rv);
					}
				}
			}
			else
			{
				printf("BAD!\n");
			}
			free(bannersav_buffer);
		}
		else
		{
			printf("unexpected bannersav elength: 0x%08x\n", le32toh(tna4->bannersav_elength));
		}

		/*if(offset_to_savedata + le32toh(tna4->savedata_elength) +
			le32toh(tna4->bannersav_elength) > st.st_size)
		{
			printf("used up too many bytes ?!\n");
		}
		else if(offset_to_savedata + le32toh(tna4->savedata_elength) +
			le32toh(tna4->bannersav_elength) != st.st_size)
		{
			printf("unused trailer of %ld bytes\n", st.st_size -
				(offset_to_savedata + le32toh(tna4->savedata_elength) +
				le32toh(tna4->bannersav_elength)));
		}*/

	}


	return 0;

}