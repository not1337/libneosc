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
#include <unistd.h>
#include <libusb.h>
#include "libneosc.h"

#define memclear(a,b,c) \
    do { memset(a,b,c); *(volatile char*)(a)=*(volatile char*)(a); } while(0)

typedef struct
{
	libusb_context *ctx;
	libusb_device_handle *handle;
} CTX;

static unsigned short crc16(unsigned char *ptr,int len)
{
	int i;
	unsigned short crc=0xffff;

	while(len--)
	{
		crc^=*ptr++;
		for(i=0;i<8;i++)if(crc&1)crc=(crc>>1)^0x8408;
		else crc>>=1;
	}
	return crc;
}

static int rset(void *handle)
{
	CTX *ctx=handle;
	unsigned char wrk[8];

	if(!ctx)return -1;

	memcpy(wrk,"\x00\x00\x00\x00\x00\x00\x00\x8f",8);
	if(libusb_claim_interface(ctx->handle,0))return -1;
	if(libusb_control_transfer(ctx->handle,
		LIBUSB_REQUEST_TYPE_CLASS|LIBUSB_ENDPOINT_OUT|
		LIBUSB_RECIPIENT_INTERFACE,0x09,0x0300,0,wrk,8,1000)<0)
	{
		libusb_release_interface(ctx->handle,0);
		return -1;
	}
	if(libusb_release_interface(ctx->handle,0))return -1;
	return 0;
}

static int tx(void *handle,int cmd,unsigned char *data,int len)
{
	CTX *ctx=handle;
	int i;
	int j;
	int s;
	unsigned short crc;
	unsigned char bfr[70];
	unsigned char wrk[8];

	if(!ctx||!data||len>64)return -1;

	memcpy(bfr,data,len);
	memset(bfr+len,0,64-len);
	crc=crc16(bfr,64);
	bfr[64]=(unsigned char)cmd;
	bfr[65]=(unsigned char)crc;
	bfr[66]=(unsigned char)(crc>>8);
	bfr[67]=0x00;
	bfr[68]=0x00;
	bfr[69]=0x00;

	for(s=0,i=0;i<70;i+=7,s++)
	{
		if(s&&s!=9)if(!memcmp(bfr+i,"\x00\x00\x00\x00\x00\x00\x00",7))
			continue;

		for(j=0;j<200;j++)
		{
			usleep(5000);
			memset(wrk,0,8);
			if(libusb_claim_interface(ctx->handle,0))goto fail;
			if(libusb_control_transfer(ctx->handle,
				LIBUSB_REQUEST_TYPE_CLASS|LIBUSB_ENDPOINT_IN|
				LIBUSB_RECIPIENT_INTERFACE,
				0x01,0x0300,0,wrk,8,1000)<0)
			{
				libusb_release_interface(ctx->handle,0);
				goto fail;
			}
			if(libusb_release_interface(ctx->handle,0))goto fail;
			if(!(wrk[7]&0x80))break;
			if(wrk[7]&0x20)
			{
				rset(handle);
				goto fail;
			}
		}
		if(j==200)goto fail;

		memcpy(wrk,bfr+i,7);
		wrk[7]=s|0x80;

		if(libusb_claim_interface(ctx->handle,0))goto fail;
		if(libusb_control_transfer(ctx->handle,
			LIBUSB_REQUEST_TYPE_CLASS|LIBUSB_ENDPOINT_OUT|
			LIBUSB_RECIPIENT_INTERFACE,0x09,0x0300,0,wrk,8,1000)<0)
		{
			libusb_release_interface(ctx->handle,0);
			goto fail;
		}
		if(libusb_release_interface(ctx->handle,0))
		{
fail:			memclear(wrk,0,8);
			memclear(bfr,0,70);
			return -1;
		}
	}

	memclear(wrk,0,8);
	memclear(bfr,0,70);
	return 0;
}

static int rx(void *handle,unsigned char *data,int *len,int dowait)
{
	CTX *ctx=handle;
	int j;
	unsigned char wrk[8];

	if(!ctx||!data||!len||!*len)return -1;

	if(*len>0)
	{
		if(*len%7)return -1;
		goto doread;
	}
	else if((*len=-*len)%7)return -1;

	usleep(10000);

	for(j=0;j<200;j++)
	{
		usleep(5000);
		memset(wrk,0,8);
		if(libusb_claim_interface(ctx->handle,0))return -1;
		if(libusb_control_transfer(ctx->handle,
			LIBUSB_REQUEST_TYPE_CLASS|LIBUSB_ENDPOINT_IN|
			LIBUSB_RECIPIENT_INTERFACE,0x01,0x0300,0,wrk,8,1000)<0)
		{
			libusb_release_interface(ctx->handle,0);
			goto fail1;
		}
		if(libusb_release_interface(ctx->handle,0))goto fail1;
		if(!(wrk[7]&0x80))break;
		if(wrk[7]&0x20)goto fail2;
	}
	if(j==200)goto fail1;

doread:	if(*len==7)
	{
		memset(wrk,0,8);
		if(libusb_claim_interface(ctx->handle,0))return -1;
		if(libusb_control_transfer(ctx->handle,
			LIBUSB_REQUEST_TYPE_CLASS|LIBUSB_ENDPOINT_IN|
			LIBUSB_RECIPIENT_INTERFACE,0x01,0x0300,0,wrk,8,1000)<0)
		{
			libusb_release_interface(ctx->handle,0);
			goto fail1;
		}
		if(libusb_release_interface(ctx->handle,0))goto fail1;
		memcpy(data,wrk,7);
		memclear(wrk,0,8);
		return 0;
	}

	for(j=0;j<200;j++)
	{
		usleep(5000);
		memset(wrk,0,8);
		if(libusb_claim_interface(ctx->handle,0))return -1;
		if(libusb_control_transfer(ctx->handle,
			LIBUSB_REQUEST_TYPE_CLASS|LIBUSB_ENDPOINT_IN|
			LIBUSB_RECIPIENT_INTERFACE,0x01,0x0300,0,wrk,8,1000)<0)
		{
			libusb_release_interface(ctx->handle,0);
			goto fail1;
		}
		if(libusb_release_interface(ctx->handle,0))goto fail1;
		if(wrk[7]&0x40)break;
		if(wrk[7]&0x20)
		{
			if(!dowait)goto fail2;
			if((wrk[7]&0x1f)>1)j=0;
		}
	}
	if(j==200)goto fail1;

	memcpy(data,wrk,7);

	for(j=7;j<*len;j+=7)
	{
repeat:		memset(wrk,0,8);
		if(libusb_claim_interface(ctx->handle,0))goto fail1;
		if(libusb_control_transfer(ctx->handle,
			LIBUSB_REQUEST_TYPE_CLASS|LIBUSB_ENDPOINT_IN|
			LIBUSB_RECIPIENT_INTERFACE,0x01,0x0300,0,wrk,8,1000)<0)
		{
			libusb_release_interface(ctx->handle,0);
			break;
		}
		if(libusb_release_interface(ctx->handle,0))break;
		if(!(wrk[7]&0x40))goto repeat;
		memcpy(data+j,wrk,7);
		if(!(wrk[7]&0x1f))
		{
			*len=j+7;
			memclear(wrk,0,8);
			rset(handle);
			return 0;
		}
	}

fail2:	rset(handle);
fail1:	memclear(wrk,0,8);
	return -1;
}

void neosc_usb_close(void *handle)
{
	CTX *ctx=handle;

	if(!ctx)return;

	libusb_attach_kernel_driver(ctx->handle,0);
	libusb_close(ctx->handle);
	libusb_exit(ctx->ctx);
	free(ctx);
}

int neosc_usb_open(void **handle,int serial,int *mode)
{
	CTX **ctx=(CTX **)handle;
	int i;
	int l;
	ssize_t n;
	libusb_device **list;
	struct libusb_device_descriptor d;
	unsigned char bfr[32];

	if(serial<0&&serial!=NEOSC_USB_YUBIKEY)goto err1;
	if(!ctx||!(*ctx=malloc(sizeof(CTX))))goto err1;

	if(libusb_init(&(*ctx)->ctx))goto err2;

	if((n=libusb_get_device_list((*ctx)->ctx,&list))<0)goto err3;

	for(i=0;i<n;i++)
	{
		if(libusb_get_device_descriptor(list[i],&d))goto err4;
		if(d.idVendor!=0x1050)continue;
		switch(d.idProduct)
		{
		case 0x0110:
			if(mode)*mode=0;
			break;
		case 0x0111:
			if(mode)*mode=2;
			break;
		case 0x0112:
			if(mode)*mode=1;
			break;
		case 0x0113:
			if(mode)*mode=3;
			break;
		case 0x0114:
			if(mode)*mode=4;
			break;
		case 0x0115:
			if(mode)*mode=5;
			break;
		case 0x0116:
			if(mode)*mode=6;
			break;
		default:continue;
		}
		if(libusb_open(list[i],&(*ctx)->handle))continue;
		if(libusb_kernel_driver_active((*ctx)->handle,0)==1)
			if(libusb_detach_kernel_driver((*ctx)->handle,0))
		{
			libusb_close((*ctx)->handle);
			continue;
		}

		if(serial==NEOSC_ANY_YUBIKEY||
			(serial==NEOSC_USB_YUBIKEY&&!d.iSerialNumber))
		{
			libusb_free_device_list(list,1);
			return 0;
		}

		if(serial&&d.iSerialNumber)
			if((l=libusb_get_string_descriptor_ascii((*ctx)->handle,
				d.iSerialNumber,bfr,sizeof(bfr)-1))>0)
		{
			bfr[l]=0;
			if(atoi((char *)bfr)==serial)
			{
				libusb_free_device_list(list,1);
				return 0;
			}
		}

		libusb_close((*ctx)->handle);
	}

err4:	libusb_free_device_list(list,1);
err3:	libusb_exit((*ctx)->ctx);
err2:	free(*ctx);
err1:	return -1;
}

int neosc_usb_read_status(void *handle,NEOSC_STATUS *status)
{
	unsigned char wrk[7];
	int len=sizeof(wrk);

	if(rx(handle,wrk,&len,0))return -1;
	status->major=wrk[1];
	status->minor=wrk[2];
	status->build=wrk[3];
	status->pgmseq=wrk[4];
	status->touchlevel=wrk[6];
	status->touchlevel<<=8;
	status->touchlevel|=wrk[5];
	status->config1=(status->touchlevel&0x01)?1:0;
	status->config2=(status->touchlevel&0x02)?1:0;
	status->touch1=(status->touchlevel&0x04)?1:0;
	status->touch2=(status->touchlevel&0x08)?1:0;
	status->ledinv=(status->touchlevel&0x10)?1:0;
	status->touchlevel&=~0x1f;
	return 0;
}

int neosc_usb_read_serial(void *handle,int *serial)
{
	unsigned char wrk[14];
	int len=sizeof(wrk);

	if(!handle||!serial)return -1;
	if(tx(handle,0x10,wrk,0))return -1;
	if(rx(handle,wrk,&len,0))return -1;
	else
	{
		*serial=wrk[0];
		*serial<<=8;
		*serial|=wrk[1];
		*serial<<=8;
		*serial|=wrk[2];
		*serial<<=8;
		*serial|=wrk[3];
	}
	return 0;
}

int neosc_usb_read_hmac(void *handle,int slot,unsigned char *in,int ilen,
	unsigned char *out,int olen)
{
	unsigned char wrk[70];
	int len=sizeof(wrk);

	if(!handle||!in||ilen<1||ilen>64||slot<0||slot>1||!out||
		olen<NEOSC_SHA1_SIZE)return -1;

	memcpy(wrk,in,ilen);
	if(ilen<64)memset(wrk+ilen,in[ilen-1]?0x00:0xff,64-ilen);
	if(tx(handle,slot?0x38:0x30,wrk,64))return -1;
	if(rx(handle,wrk,&len,1)||len<NEOSC_SHA1_SIZE)
	{
		memclear(wrk,0,70);
		return -1;
	}
	memcpy(out,wrk,NEOSC_SHA1_SIZE);
	memclear(wrk,0,70);
	return 0;
}

int neosc_usb_read_otp(void *handle,int slot,unsigned char *in,int ilen,
	unsigned char *out,int olen)
{
	unsigned char wrk[70];
	int len=sizeof(wrk);

	if(!handle||!in||ilen!=6||slot<0||slot>1||!out||olen<16)return -1;

	if(tx(handle,slot?0x28:0x20,in,ilen))return -1;
	if(rx(handle,wrk,&len,1)||len<16)
	{
		memclear(wrk,0,70);
		return -1;
	}
	memcpy(out,wrk,16);
	memclear(wrk,0,70);
	return 0;
}

int neosc_usb_write_ndef(void *handle,int slot,char *url,char *txt,char *lang,
	unsigned char *code,int codelen)
{
	int len;
	int seq;
	int id;
	int retry=1;
	unsigned char wrk[62];

	if(!handle||(slot^(slot&1)))return -1;
	if(!url&&!txt)return -1;
	if(url&&txt)return -1;
	if(txt&&!lang)return -1;
	if(code&&codelen!=6)return -1;

repeat:	len=7;
	if(rx(handle,wrk,&len,0))return -1;
	seq=wrk[4];

	memset(wrk,0,sizeof(wrk));

	if(url)
	{
		id=neosc_util_uri2id(url);
		url+=strlen(neosc_util_id2uri(id));
		if((len=strlen(url))>53)return -1;
		wrk[0]=(unsigned char)(len+1);
		wrk[1]=0x55;
		wrk[2]=(unsigned char)id;
		memcpy(wrk+3,url,len);
	}
	else
	{
		len=strlen(txt);
		id=strlen(lang);
		if(len+id>53)return -1;
		wrk[0]=(unsigned char)(len+id+1);
		wrk[1]=0x54;
		wrk[2]=(unsigned char)id;
		memcpy(wrk+3,lang,id);
		memcpy(wrk+3+id,txt,len);
	}

	if(code)memcpy(wrk+56,code,6);

	if(tx(handle,slot?0x09:0x08,wrk,62))
	{
		memclear(wrk,0,62);
		return -1;
	}
	memclear(wrk,0,62);

	len=-7;
	if(rx(handle,wrk,&len,0))return -1;

	if(seq==wrk[4])
	{
		if(!retry--)return -1;
		usleep(250000);
		goto repeat;
	}

	return 0;
}

int neosc_usb_write_scanmap(void *handle,unsigned char *map,int maplen)
{
	int len;
	int seq;
	int retry=1;
	unsigned char wrk[45];

	if(!handle||(map&&maplen!=45))return -1;

repeat:	len=7;
	if(rx(handle,wrk,&len,0))return -1;
	seq=wrk[4];

	if(!map)memset(wrk,0,45);
	if(tx(handle,0x12,map?map:wrk,45))return -1;

	len=-7;
	if(rx(handle,wrk,&len,0))return -1;

	if(seq==wrk[4])
	{
		if(!retry--)return -1;
		usleep(250000);
		goto repeat;
	}

	return 0;
}

int neosc_usb_setmode(void *handle,int mode,int crtimeout,int autoejecttime)
{
	int len;
	int seq;
	int retry=1;
	unsigned char wrk[7];

	if(!handle||(mode&~0x87)||(mode&0x7)==0x07||crtimeout<0||crtimeout>255||
		autoejecttime<0||autoejecttime>65535)return -1;

repeat:	len=7;
	if(rx(handle,wrk,&len,0))return -1;
	seq=wrk[4];

	wrk[0]=(unsigned char)mode;
	wrk[1]=(unsigned char)crtimeout;
	wrk[2]=(unsigned char)autoejecttime;
	wrk[3]=(unsigned char)(autoejecttime>>8);

	if(tx(handle,0x11,wrk,4))
	{
		memclear(wrk,0,4);
		return -1;
	}
	memclear(wrk,0,4);

	len=-7;
	if(rx(handle,wrk,&len,0))return -1;

	if(seq==wrk[4])
	{
		if(!retry--)return -1;
		usleep(250000);
		goto repeat;
	}

	return 0;
}

int neosc_usb_reset(void *handle,int slot)
{
	int len;
	int seq;
	int retry=1;
	unsigned char wrk[58];

	if(!handle||(slot^(slot&1)))return -1;

repeat:	len=7;
	if(rx(handle,wrk,&len,0))return -1;
	seq=wrk[4];

	memset(wrk,0,58);

	if(tx(handle,slot?0x03:0x01,wrk,58))return -1;

	len=-7;
	if(rx(handle,wrk,&len,0))return -1;

	if(!(wrk[5]&0x03)&&!wrk[4])return 0;

	if(seq==wrk[4])
	{
		if(!retry--)return -1;
		usleep(250000);
		goto repeat;
	}

	return 0;
}

int neosc_usb_config(void *handle,int command,int tktflags,int cfgflags,
	int extflags,unsigned char *fixeddata,int fixedlen,
	unsigned char *uidpart,int uidlen,unsigned char *aesdata,int aeslen,
	unsigned char *newcode,int newlen,unsigned char *code,int codelen)
{
	int len;
	int seq;
	int retry=1;
	unsigned short crc;
	unsigned char wrk[58];

	if(!handle)return -1;
	if(code&&codelen!=6)return -1;
	if(newcode&&newlen!=6)return -1;
	if(fixeddata)if(fixedlen<0||fixedlen>16)return -1;
	if(uidpart&&uidlen!=4&&uidlen!=6)return -1;
	if(aesdata&&aeslen!=16)return -1;

repeat:	len=7;
	if(rx(handle,wrk,&len,0))return -1;
	seq=wrk[4];

	memset(wrk,0,58);
	if(fixeddata)
	{
		memcpy(wrk,fixeddata,fixedlen);
		wrk[44]=(unsigned char)fixedlen;
	}
	if(uidpart)memcpy(wrk+16,uidpart,uidlen);
	if(aesdata)memcpy(wrk+22,aesdata,16);
	if(newcode)memcpy(wrk+38,newcode,6);
	wrk[45]=(unsigned char)extflags;
	wrk[46]=(unsigned char)tktflags;
	wrk[47]=(unsigned char)cfgflags;
	crc=~crc16(wrk,50);
	wrk[50]=(unsigned char)crc;
	wrk[51]=(unsigned char)(crc>>8);
	if(code)memcpy(wrk+52,code,6);

	if(tx(handle,command,wrk,58))
	{
		memclear(wrk,0,58);
		return -1;
	}
	memclear(wrk,0,58);

	len=-7;
	if(rx(handle,wrk,&len,0))return -1;

	if(seq==wrk[4])
	{
		if(!retry--)return -1;
		usleep(250000);
		goto repeat;
	}

	return 0;
}

int neosc_usb_swap(void *handle,unsigned char *newcode,int newlen,
	unsigned char *code,int codelen)
{
	return neosc_usb_config(handle,0x06,0,0,0,NULL,0,NULL,0,NULL,0,
		newcode,newlen,code,codelen);
}

int neosc_usb_update(void *handle,int slot,int tktflags,int cfgflags,
	int extflags,unsigned char *newcode,int newlen,unsigned char *code,
	int codelen)
{
	if(slot^(slot&1))return -1;
	if((tktflags&~0x3f)||(cfgflags&~0x0c)||(extflags&~0xff))return -1;
	if((extflags&0x60)==0x40)return -1;

	return neosc_usb_config(handle,slot?0x05:0x04,tktflags,cfgflags,
		extflags,NULL,0,NULL,0,NULL,0,newcode,newlen,code,codelen);
}

int neosc_usb_hmac(void *handle,int slot,unsigned char *aesdata,int aeslen,
	int tktflags,int cfgflags,int extflags,unsigned char *newcode,
	int newlen,unsigned char *code,int codelen)
{
	if((slot^(slot&1))||!aesdata||aeslen!=20||(tktflags&~0x80)||
		(cfgflags&~0x0c)||(extflags&~0xff))return -1;
	if((extflags&0x60)==0x40)return -1;

	return neosc_usb_config(handle,slot?0x03:0x01,tktflags|0x40,
		cfgflags|0x22,extflags,NULL,0,aesdata+16,4,aesdata,16,
		newcode,newlen,code,codelen);
}

int neosc_usb_otp(void *handle,int slot,unsigned char *privid,int privlen,
	unsigned char *aesdata,int aeslen,int tktflags,int cfgflags,
	int extflags,unsigned char *newcode,int newlen,unsigned char *code,
	int codelen)
{
	if((slot^(slot&1))||!aesdata||aeslen!=16||(tktflags&~0x80)||
		(cfgflags&~0x08)||(extflags&~0xff))return -1;
	if((extflags&0x60)==0x40)return -1;
	if(privid&&privlen!=6)return -1;

	return neosc_usb_config(handle,slot?0x03:0x01,tktflags|0x40,
		cfgflags|0x20,extflags,NULL,0,privid,6,aesdata,16,
		newcode,newlen,code,codelen);
}

int neosc_usb_hotp(void *handle,int slot,int omp,int tt,int mui,int imf,
	unsigned char *aesdata,int aeslen,int tktflags,int cfgflags,
	int extflags,unsigned char *newcode,int newlen,unsigned char *code,
	int codelen)
{
	int r;
	int fixedlen=0;
	unsigned char uidpart[6];
	unsigned char fixeddata[6];

	if((slot^(slot&1))||!aesdata||aeslen!=20||(tktflags&~0xbf)||
		(cfgflags&~0x5f)||(extflags&~0xff))return -1;
	if((extflags&0x60)==0x40)return -1;
	if(omp<0||omp>255||tt<0||tt>255||mui<-1||mui>99999999)return -1;
	if(imf<0||imf>0xffff0||(imf&0xf))return -1;

	if(mui>=0)
	{
		fixedlen=6;
		fixeddata[0]=(unsigned char)omp;
		fixeddata[1]=(unsigned char)tt;
		fixeddata[2]=(unsigned char)
				(((mui/10000000)<<4)|((mui/1000000)%10));
		fixeddata[3]=(unsigned char)
				((((mui/100000)%10)<<4)|((mui/10000)%10));
		fixeddata[4]=(unsigned char)
				((((mui/1000)%10)<<4)|((mui/100)%10));
		fixeddata[5]=(unsigned char)((((mui/10)%10)<<4)|(mui%10));
	}
	else if(cfgflags&0x50)return -1;

	uidpart[0]=aesdata[16];
	uidpart[1]=aesdata[17];
	uidpart[2]=aesdata[18];
	uidpart[3]=aesdata[19];
	uidpart[4]=(unsigned char)(imf>>12);
	uidpart[5]=(unsigned char)(imf>>4);

	r=neosc_usb_config(handle,slot?0x03:0x01,tktflags|0x40,
		cfgflags,extflags,fixedlen?fixeddata:NULL,fixedlen,uidpart,6,
		aesdata,16,newcode,newlen,code,codelen);

	memclear(uidpart,0,6);
	memclear(fixeddata,0,6);
	return r;
}

int neosc_usb_yubiotp(void *handle,int slot,unsigned char *pubid,int publen,
	unsigned char *privid,int privlen,unsigned char *aesdata,int aeslen,
	int tktflags,int cfgflags,int extflags,unsigned char *newcode,
	int newlen,unsigned char *code,int codelen)
{
	if((slot^(slot&1))||!aesdata||aeslen!=16||(tktflags&~0xbf)||
		(cfgflags&~0x0d)||(extflags&~0xff))return -1;
	if((extflags&0x60)==0x40)return -1;
	if(privid&&privlen!=6)return -1;

	return neosc_usb_config(handle,slot?0x03:0x01,tktflags,cfgflags,
		extflags,pubid,publen,privid,privlen,aesdata,16,newcode,newlen,
		code,codelen);
}

int neosc_usb_passwd(void *handle,int slot,unsigned char *pubid,int publen,
	unsigned char *privid,int privlen,unsigned char *aesdata,int aeslen,
	int tktflags,int cfgflags,int extflags,unsigned char *newcode,
	int newlen,unsigned char *code,int codelen)
{
	if((slot^(slot&1))||!aesdata||aeslen!=16||(tktflags&~0xbf)||
		(cfgflags&~0xdf)||(extflags&~0xff))return -1;
	if((extflags&0x60)==0x40)return -1;
	if(!privid||privlen!=6)return -1;
	if(pubid&&publen<=0)return -1;
	if((cfgflags&0x02)&&pubid)return -1;
	if((cfgflags&0x41)==0x01)return -1;

	return neosc_usb_config(handle,slot?0x03:0x01,tktflags,cfgflags|0x20,
		extflags,pubid,publen,privid,privlen,aesdata,16,newcode,newlen,
		code,codelen);
}
