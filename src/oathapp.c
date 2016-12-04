/* 
 * libneosc - an easy access library to the YubiKey NEO(-N)
 *
 * Copyright (c) 2015 Andreas Steinmetz, ast@domdv.de
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA  02110-1301  USA
 */

#include <string.h>
#include <stdlib.h>
#include "libneosc.h"

#define memclear(a,b,c) \
    do { memset(a,b,c); *(volatile char*)(a)=*(volatile char*)(a); } while(0)

static unsigned char sel_oath[]=
{
	0x00,0xA4,0x04,0x00,0x08,0xa0,0x00,0x00,0x05,0x27,0x21,0x01,0x01
};

static unsigned char list_cmd[]=
{
	0x00,0xa1,0x00,0x00
};

static unsigned char single_cmd[]=
{
	0x00,0xa2,0x00,0x01
};

static unsigned char unlock_cmd[]=
{
	0x00,0xa3,0x00,0x00,0x20,0x75,NEOSC_SHA1_SIZE
};

static unsigned char all_cmd[]=
{
	0x00,0xa4,0x00,0x01,0x0a,0x74,0x08
};

static unsigned char next_cmd[]=
{
	0x00,0xa5,0x00,0x00
};

static unsigned char add_cmd[]=
{
	0x00,0x01,0x00,0x00
};

static unsigned char delete_cmd[]=
{
	0x00,0x02,0x00,0x00
};

static unsigned char chgpass_cmd[]=
{
	0x00,0x03,0x00,0x00
};

static unsigned char reset_cmd[]=
{
	0x00,0x04,0xde,0xad
};

int neosc_oath_select(void *ctx,NEOSC_OATH_INFO *info)
{
	int status;
	unsigned char bfr[28];
	int len=sizeof(bfr);

	if(!ctx)return -1;

	if(neosc_pcsc_apdu(ctx,sel_oath,sizeof(sel_oath),bfr,&len,&status)||
		status!=0x9000||len<15)return -1;

	if(bfr[0]!=0x79||bfr[1]!=0x03||bfr[5]!=0x71||bfr[6]!=0x08)return -1;
	if(len>15)switch(len)
	{
	case 28:if(bfr[25]!=0x7b||bfr[26]!=0x01)return -1;
	case 25:if(bfr[15]!=0x74||bfr[16]!=0x08)return -1;
		break;
	default:return -1;
	}
	if(info)
	{
		info->major=bfr[2];
		info->minor=bfr[3];
		info->build=bfr[4];
		memcpy(info->identity,bfr+7,8);
		if(len==15)
		{
			info->protected=0;
			memset(info->challenge,0,8);
		}
		else
		{
			info->protected=1;
			memcpy(info->challenge,bfr+17,8);
		}
	}
	return 0;
}

int neosc_oath_reset(void *ctx)
{
	int status;

	if(neosc_pcsc_apdu(ctx,reset_cmd,sizeof(reset_cmd),NULL,NULL,&status)||
		status!=0x9000)return -1;
	return 0;
}

int neosc_oath_unlock(void *ctx,char *password,NEOSC_OATH_INFO *info)
{
	int status;
	NEOSC_SHA1HMDATA hmdata;
	unsigned char bfr[sizeof(unlock_cmd)+NEOSC_SHA1_SIZE+10];

	if(!ctx||!password||!info)return -1;

	if(!info->protected)return 0;

	if(neosc_util_random(bfr+sizeof(unlock_cmd)+NEOSC_SHA1_SIZE+2,8))
		return -1;
	memcpy(bfr,unlock_cmd,sizeof(unlock_cmd));
	neosc_pbkdf2(password,info->identity,8,1000,bfr+sizeof(unlock_cmd),16);
	neosc_sha1hmkey(bfr+sizeof(unlock_cmd),16,&hmdata);
	neosc_sha1hmac(info->challenge,8,bfr+sizeof(unlock_cmd),&hmdata);
	memclear(&hmdata,0,sizeof(hmdata));
	bfr[sizeof(unlock_cmd)+NEOSC_SHA1_SIZE]=0x74;
	bfr[sizeof(unlock_cmd)+NEOSC_SHA1_SIZE+1]=0x08;
	if(neosc_pcsc_apdu(ctx,bfr,sizeof(bfr),NULL,NULL,&status)||
		status!=0x9000)
	{
		memclear(bfr,0,sizeof(bfr));
		return -1;
	}
	memclear(bfr,0,sizeof(bfr));
	return 0;
}

int neosc_oath_chgpass(void *ctx,char *password,NEOSC_OATH_INFO *info)
{
	int status;
	NEOSC_SHA1HMDATA hmdata;
	unsigned char bfr[sizeof(chgpass_cmd)+52];

	if(!ctx||!password)return -1;

	if(!*password)
	{
		memcpy(bfr,chgpass_cmd,sizeof(chgpass_cmd));
		memcpy(bfr+sizeof(chgpass_cmd),"\x02\x73\x00",3);
		if(neosc_pcsc_apdu(ctx,bfr,sizeof(chgpass_cmd)+3,NULL,NULL,
			&status)||status!=0x9000)return -1;
		return 0;
	}

	if(!info)return -1;

	if(neosc_util_random(bfr+sizeof(chgpass_cmd)+22,8))return -1;
	memcpy(bfr,chgpass_cmd,sizeof(chgpass_cmd));
	memcpy(bfr+sizeof(chgpass_cmd),"\x33\x73\x11\x21",4);
	bfr[sizeof(chgpass_cmd)+20]=0x74;
	bfr[sizeof(chgpass_cmd)+21]=0x08;
	bfr[sizeof(chgpass_cmd)+30]=0x75;
	bfr[sizeof(chgpass_cmd)+31]=NEOSC_SHA1_SIZE;
	neosc_pbkdf2(password,info->identity,8,1000,
		bfr+sizeof(chgpass_cmd)+4,16);
	neosc_sha1hmkey(bfr+sizeof(chgpass_cmd)+4,16,&hmdata);
	neosc_sha1hmac(bfr+sizeof(chgpass_cmd)+22,8,
		bfr+sizeof(chgpass_cmd)+32,&hmdata);
	memclear(&hmdata,0,sizeof(hmdata));
	if(neosc_pcsc_apdu(ctx,bfr,sizeof(bfr),NULL,NULL,&status)||
		status!=0x9000)
	{
		memclear(bfr,0,sizeof(bfr));
		return -1;
	}
	memclear(bfr,0,sizeof(bfr));
	return 0;
}

int neosc_oath_calc_single(void *ctx,char *name,time_t time,
	NEOSC_OATH_RESPONSE *result)
{
	int status;
	int nlen;
	unsigned char bfr[sizeof(single_cmd)+NEOSC_OATH_NAMELEN+13];
	int olen=sizeof(bfr);

	if(!ctx||!name||!result)return -1;
	nlen=strlen(name);
	if(nlen<0||nlen>NEOSC_OATH_NAMELEN)return -1;

	memcpy(bfr,single_cmd,sizeof(single_cmd));
	bfr[sizeof(single_cmd)]=nlen+12;
	bfr[sizeof(single_cmd)+1]=0x71;
	bfr[sizeof(single_cmd)+2]=(unsigned char)nlen;
	memcpy(bfr+sizeof(single_cmd)+3,name,nlen);
	bfr[sizeof(single_cmd)+nlen+3]=0x74;
	bfr[sizeof(single_cmd)+nlen+4]=8;
	neosc_util_time_to_array(time,bfr+sizeof(single_cmd)+nlen+5,8);

	if(neosc_pcsc_apdu(ctx,bfr,sizeof(single_cmd)+nlen+13,bfr,&olen,
		&status)||status!=0x9000||olen!=7)return -1;

	if(bfr[0]!=0x76||bfr[1]!=0x05)return -1;
	result->digits=bfr[2];
	result->value=bfr[3];
	result->value<<=8;
	result->value|=bfr[4];
	result->value<<=8;
	result->value|=bfr[5];
	result->value<<=8;
	result->value|=bfr[6];
	switch(bfr[2])
	{
	case 6:	result->value%=1000000;
		break;
	case 7:	result->value%=10000000;
		break;
	case 8:	result->value%=100000000;
		break;
	default:return -1;
	}
	strcpy(result->name,name);
	return 0;
}

int neosc_oath_calc_all(void *ctx,time_t time,NEOSC_OATH_RESPONSE **result,
	int *total)
{
	int status;
	unsigned char bfr[4096];
	int len=sizeof(bfr);
	int olen=0;
	int pos=0;
	int curr=0;
	int alloc=0;
	NEOSC_OATH_RESPONSE *data=NULL;
	NEOSC_OATH_RESPONSE *tmp;

	if(!ctx||!total||!result)return -1;

	memcpy(bfr,all_cmd,sizeof(all_cmd));
	neosc_util_time_to_array(time,bfr+sizeof(all_cmd),8);

	if(neosc_pcsc_apdu(ctx,bfr,sizeof(all_cmd)+8,bfr,&len,&status))
		return -1;
	while((status&0xff00)==0x6100)
	{
		olen+=len;
		len=sizeof(bfr)-olen;
		if(neosc_pcsc_apdu(ctx,next_cmd,sizeof(next_cmd),bfr+olen,&len,
			&status))return -1;
	}
	if(status!=0x9000)return -1;
	olen+=len;

	while(pos<olen)
	{
		if(curr==alloc)
		{
			alloc+=16;
			if(!(tmp=realloc(data,
				alloc*sizeof(NEOSC_OATH_RESPONSE))))goto fail;
			data=tmp;
		}

		if(pos+2>=olen||bfr[pos++]!=0x71)goto fail;
		len=bfr[pos++];
		if(len>NEOSC_OATH_NAMELEN||pos+len>=olen)goto fail;
		memcpy(data[curr].name,bfr+pos,len);
		data[curr].name[len]=0;
		pos+=len;
		switch(bfr[pos++])
		{
		case 0x77:
			if(pos>=olen||pos+bfr[pos]+1>olen)goto fail;
			pos+=bfr[pos]+1;
			break;

		case 0x76:
			if(pos>=olen||bfr[pos]!=0x05||pos+bfr[pos]+1>olen)
				goto fail;
			data[curr].digits=bfr[pos+1];
			data[curr].value=bfr[pos+2];
			data[curr].value<<=8;
			data[curr].value|=bfr[pos+3];
			data[curr].value<<=8;
			data[curr].value|=bfr[pos+4];
			data[curr].value<<=8;
			data[curr].value|=bfr[pos+5];
			switch(bfr[pos+1])
			{
			case 6:	data[curr].value%=1000000;
				break;
			case 7:	data[curr].value%=10000000;
				break;
			case 8:	data[curr].value%=100000000;
				break;
			default:return -1;
			}
			pos+=bfr[pos]+1;
			curr++;
			break;

		default:return -1;
		}
	}

	if(alloc>curr)if((tmp=realloc(data,curr*sizeof(NEOSC_OATH_RESPONSE))))
		data=tmp;

	*result=data;
	*total=curr;

	return 0;

fail:	if(data)free(data);
	return -1;
}

int neosc_oath_list_all(void *ctx,NEOSC_OATH_LIST **result,int *total)
{
	int status;
	unsigned char bfr[4096];
	int len=sizeof(bfr);
	int olen=0;
	int pos=0;
	int curr=0;
	int alloc=0;
	NEOSC_OATH_LIST *data=NULL;
	NEOSC_OATH_LIST *tmp;

	if(!ctx||!total||!result)return -1;

	if(neosc_pcsc_apdu(ctx,list_cmd,sizeof(list_cmd),bfr,&len,&status))
		return -1;
	while((status&0xff00)==0x6100)
	{
		olen+=len;
		len=sizeof(bfr)-olen;
		if(neosc_pcsc_apdu(ctx,next_cmd,sizeof(next_cmd),bfr+olen,&len,
			&status))return -1;
	}
	if(status!=0x9000)return -1;
	olen+=len;

	while(pos<olen)
	{
		if(curr==alloc)
		{
			alloc+=16;
			if(!(tmp=realloc(data,
				alloc*sizeof(NEOSC_OATH_LIST))))goto fail;
			data=tmp;
		}

		if(pos+2>=olen||bfr[pos++]!=0x72)goto fail;
		len=bfr[pos++];
		if(len-1>NEOSC_OATH_NAMELEN||pos+len>olen)goto fail;
		switch(bfr[pos++])
		{
		case 0x11:
			data[curr].otpmode=NEOSC_OATH_HOTP;
			data[curr].shamode=NEOSC_OATH_SHA1;
			break;
		case 0x12:
			data[curr].otpmode=NEOSC_OATH_HOTP;
			data[curr].shamode=NEOSC_OATH_SHA256;
			break;
		case 0x21:
			data[curr].otpmode=NEOSC_OATH_TOTP;
			data[curr].shamode=NEOSC_OATH_SHA1;
			break;
		case 0x22:
			data[curr].otpmode=NEOSC_OATH_TOTP;
			data[curr].shamode=NEOSC_OATH_SHA256;
			break;
		default:goto fail;
		}
		memcpy(data[curr].name,bfr+pos,len-1);
		data[curr].name[len-1]=0;
		pos+=len-1;
		curr++;
	}

	if(alloc>curr)if((tmp=realloc(data,curr*sizeof(NEOSC_OATH_RESPONSE))))
		data=tmp;

	*result=data;
	*total=curr;

	return 0;

fail:	if(data)free(data);
	return -1;
}

int neosc_oath_delete(void *ctx,char *name)
{
	int status;
	int len;
	unsigned char bfr[sizeof(delete_cmd)+NEOSC_OATH_NAMELEN+2];

	if(!ctx||!name||!*name||(len=strlen(name))>NEOSC_OATH_NAMELEN)return -1;

	memcpy(bfr,delete_cmd,sizeof(delete_cmd));
	bfr[sizeof(delete_cmd)]=len+2;
	bfr[sizeof(delete_cmd)+1]=0x71;
	bfr[sizeof(delete_cmd)+2]=len;
	memcpy(bfr+sizeof(delete_cmd)+3,name,len);
	if(neosc_pcsc_apdu(ctx,bfr,sizeof(delete_cmd)+len+3,NULL,NULL,&status)||
		status!=0x9000)return -1;
	return 0;
}

int neosc_oath_add(void *ctx,char *name,int otpmode,int shamode,int digits,
	unsigned int counter,unsigned char *secret,int slen)
{
	int status;
	int len;
	unsigned char bfr[sizeof(add_cmd)+NEOSC_OATH_NAMELEN+33];

	if(!ctx||!name||!*name||(len=strlen(name))>NEOSC_OATH_NAMELEN||
		(otpmode^(otpmode&1))||(shamode^(shamode&1))||digits<6||
		digits>8||!secret||slen!=
			(shamode?NEOSC_SHA256_SIZE:NEOSC_SHA1_SIZE))return -1;

	memcpy(bfr,add_cmd,sizeof(add_cmd));
	bfr[sizeof(add_cmd)]=len+26+(counter?6:0);
	bfr[sizeof(add_cmd)+1]=0x71;
	bfr[sizeof(add_cmd)+2]=len;
	memcpy(bfr+sizeof(add_cmd)+3,name,len);
	bfr[sizeof(add_cmd)+len+3]=0x73;
	bfr[sizeof(add_cmd)+len+4]=0x16;
	bfr[sizeof(add_cmd)+len+5]=(otpmode?0x21:0x11)+shamode;
	bfr[sizeof(add_cmd)+len+6]=digits;
	memcpy(bfr+sizeof(add_cmd)+len+7,secret,NEOSC_SHA1_SIZE);
	len+=27;
	if(counter)
	{
		bfr[sizeof(add_cmd)+len]=0x7a;
		bfr[sizeof(add_cmd)+len+1]=0x04;
		bfr[sizeof(add_cmd)+len+2]=(unsigned char)(counter>>24);
		bfr[sizeof(add_cmd)+len+3]=(unsigned char)(counter>>16);
		bfr[sizeof(add_cmd)+len+4]=(unsigned char)(counter>>8);
		bfr[sizeof(add_cmd)+len+5]=(unsigned char)counter;
		len+=6;
	}
	if(neosc_pcsc_apdu(ctx,bfr,sizeof(add_cmd)+len,NULL,NULL,&status)||
		status!=0x9000)
	{
		memclear(bfr,0,sizeof(bfr));
		return -1;
	}
	memclear(bfr,0,sizeof(bfr));
	return 0;
}
