/* 
 * libneosc - an easy access library to the YubiKey NEO(-N)/4 (nano)
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

#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include "libneosc.h"

#define memclear(a,b,c) \
    do { memset(a,b,c); *(volatile char*)(a)=*(volatile char*)(a); } while(0)

static char *uritab[0x24]=
{
	"",
	"http://www.",
	"https://www.",
	"http://",
	"https://",
	"tel:",
	"mailto:",
	"ftp://anonymous:anonymous@",
	"ftp://ftp.",
	"ftps://",
	"sftp://",
	"smb://",
	"nfs://",
	"ftp://",
	"dav://",
	"news:",
	"telnet://",
	"imap:",
	"rtsp://",
	"urn:",
	"pop:",
	"sip:",
	"sips:",
	"tftp:",
	"btspp://",
	"btl2cap://",
	"btgoep://",
	"tcpobex://",
	"irdaobex://",
	"file://",
	"urn:epc:id:",
	"urn:epc:tag:",
	"urn:epc:pat:",
	"urn:epc:raw:",
	"urn:epc:",
	"urn:nfc:"
};

char *neosc_util_id2uri(int id)
{
	if(id<0x24)return uritab[id];
	else return uritab[0];
}

int neosc_util_uri2id(char *uri)
{
	int i;

	for(i=0x01;i<0x24;i++)if(!strncmp(uri,uritab[i],strlen(uritab[i])))
		return i;
	return 0;
}

int neosc_util_sha1_to_otp(unsigned char *in,int ilen,int digits,int *out)
{
	int idx;
	unsigned int num;

	if(!in||ilen!=NEOSC_SHA1_SIZE||digits<6||digits>8||!out)return -1;

	idx=in[19]&0xf;
	num=in[idx]&0x7f;
	num<<=8;
	num|=in[idx+1];
	num<<=8;
	num|=in[idx+2];
	num<<=8;
	num|=in[idx+3];
	switch(digits)
	{
	case 6:	*out=num%1000000;
		break;
	case 7:	*out=num%10000000;
		break;
	case 8:	*out=num%100000000;
		break;
	}
	return 0;
}

int neosc_util_time_to_array(time_t time,unsigned char *out,int olen)
{
	if(!out||olen<8)return -1;

	time/=NEOSC_OATH_STEP;
	*out++=0x00;
	*out++=0x00;
	*out++=0x00;
	*out++=0x00;
	*out++=(unsigned char)(time>>24);
	*out++=(unsigned char)(time>>16);
	*out++=(unsigned char)(time>>8);
	*out++=(unsigned char)time;
	return 0;
}

int neosc_util_random(unsigned char *out,int olen)
{
	int fd;
	int len;

	if(!out||olen<0)return -1;
	if(!olen)return 0;

	if((fd=open("/dev/urandom",O_RDONLY|O_CLOEXEC))==-1)return -1;
	while(olen)switch((len=read(fd,out,olen)))
	{
	case -1:if(errno==EINTR)continue;
	case 0:	close(fd);
		return -1;
	default:out+=len;
		olen-=len;
		break;
	}
	close(fd);
	return 0;
}

int neosc_util_modhex_encode(unsigned char *in,int ilen,char *out,int *olen)
{
	static char *modhex="cbdefghijklnrtuv";

	if(!in||ilen<0||!out||!olen||*olen<(ilen<<1)+1)return -1;

	for(*olen=0;ilen--;in++)
	{
		out[(*olen)++]=modhex[*in>>4];
		out[(*olen)++]=modhex[*in&0xf];
	}
	out[*olen]=0;
	return 0;
}

int neosc_util_modhex_decode(char *in,int ilen,unsigned char *out,int *olen)
{
	unsigned char n;
	int f;

	if(!in||ilen<0||!out||!olen||*olen<((ilen+1)>>1))return -1;

	if((f=ilen&1))*out=0x00;
	for(*olen=0;ilen--;f^=1,in++)
	{
		switch((*in>='A'&&*in<='Z'?*in|0x20:*in))
		{
		case 'c':n=0x00;break;
		case 'b':n=0x01;break;
		case 'd':n=0x02;break;
		case 'e':n=0x03;break;
		case 'f':n=0x04;break;
		case 'g':n=0x05;break;
		case 'h':n=0x06;break;
		case 'i':n=0x07;break;
		case 'j':n=0x08;break;
		case 'k':n=0x09;break;
		case 'l':n=0x0a;break;
		case 'n':n=0x0b;break;
		case 'r':n=0x0c;break;
		case 't':n=0x0d;break;
		case 'u':n=0x0e;break;
		case 'v':n=0x0f;break;
		default:return -1;
		}
		if(!f)out[*olen]=n<<4;
		else out[(*olen)++]|=n;
	}
	return 0;
}

int neosc_util_hex_encode(unsigned char *in,int ilen,char *out,int *olen)
{
	static char *hex="0123456789abcdef";

	if(!in||ilen<0||!out||!olen||*olen<(ilen<<1)+1)return -1;

	for(*olen=0;ilen--;in++)
	{
		out[(*olen)++]=hex[*in>>4];
		out[(*olen)++]=hex[*in&0xf];
	}
	out[*olen]=0;
	return 0;
}

int neosc_util_hex_decode(char *in,int ilen,unsigned char *out,int *olen)
{
	unsigned char n;
	int f;

	if(!in||ilen<0||!out||!olen||*olen<((ilen+1)>>1))return -1;

	if((f=ilen&1))*out=0x00;
	for(*olen=0;ilen--;f^=1,in++)
	{
		if(*in>='0'&&*in<='9')n=*in-'0';
		else if(*in>='A'&&*in<='F')n=*in-'A'+10;
		else if(*in>='a'&&*in<='f')n=*in-'a'+10;
		else return -1;
		if(!f)out[*olen]=n<<4;
		else out[(*olen)++]|=n;
	}
	return 0;
}

int neosc_util_base64_encode(unsigned char *in,int ilen,char *out,int *olen)
{
	static char *b64="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef"
			 "ghijklmnopqrstuvwxyz0123456789+/";

	if(!in||ilen<0||!out||!olen||*olen<(((ilen+2)/3)<<2)+1)return -1;

	for(*olen=0;ilen>2;ilen-=3,in+=3)
	{
		out[(*olen)++]=b64[in[0]>>2];
		out[(*olen)++]=b64[((in[0]<<4)&0x3f)|(in[1]>>4)];
		out[(*olen)++]=b64[((in[1]<<2)&0x3f)|(in[2]>>6)];
		out[(*olen)++]=b64[in[2]&0x3f];
	}
	switch(ilen)
	{
	case 1:	out[(*olen)++]=b64[in[0]>>2];
		out[(*olen)++]=b64[((in[0]<<4)&0x3f)];
		out[(*olen)++]='=';
		out[(*olen)++]='=';
		break;
	case 2:	out[(*olen)++]=b64[in[0]>>2];
		out[(*olen)++]=b64[((in[0]<<4)&0x3f)|(in[1]>>4)];
		out[(*olen)++]=b64[((in[1]<<2)&0x3f)];
		out[(*olen)++]='=';
		break;
	}
	out[*olen]=0;
	return 0;
}

int neosc_util_base64_decode(char *in,int ilen,unsigned char *out,int *olen)
{
	int i;
	unsigned char n;
	unsigned char r=0;

	if(!in||ilen<0||(ilen&3)||!out||!olen)return -1;
	if(ilen)
	{
		if(in[ilen-1]=='=')ilen--;
		if(in[ilen-1]=='=')ilen--;
	}
	if(*olen<((ilen&3)?(ilen>>2)*3+(ilen&3)-1:(ilen>>2)*3))return -1;

	for(i=0,*olen=0;ilen--;i=(i+1)&3,in++)
	{
		if(*in>='A'&&*in<='Z')n=*in-'A';
		else if(*in>='a'&&*in<='z')n=*in-'a'+26;
		else if(*in>='0'&&*in<='9')n=*in-'0'+52;
		else if(*in=='+')n=62;
		else if(*in=='/')n=63;
		else return -1;

		switch(i)
		{
		case 0: out[*olen]=n<<2;
			break;
		case 1:	out[(*olen)++]|=n>>4;
			r=n<<4;
			break;
		case 2:	out[(*olen)++]=r|(n>>2);
			r=n<<6;
			break;
		case 3:	out[(*olen)++]=r|n;
			break;
		}
	}
	return 0;
}

int neosc_util_base32_encode(unsigned char *in,int ilen,char *out,int *olen)
{
	static char *b32="ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

	if(!in||ilen<0||!out||!olen||*olen<(((ilen+4)/5)<<3)+1)return -1;

	for(*olen=0;ilen>4;ilen-=5,in+=5)
	{
		out[(*olen)++]=b32[in[0]>>3];
		out[(*olen)++]=b32[((in[0]<<2)&0x1f)|(in[1]>>6)];
		out[(*olen)++]=b32[(in[1]>>1)&0x1f];
		out[(*olen)++]=b32[((in[1]<<4)&0x1f)|(in[2]>>4)];
		out[(*olen)++]=b32[((in[2]<<1)&0x1f)|(in[3]>>7)];
		out[(*olen)++]=b32[(in[3]>>2)&0x1f];
		out[(*olen)++]=b32[((in[3]<<3)&0x1f)|(in[4]>>5)];
		out[(*olen)++]=b32[in[4]&0x1f];
	}
	switch(ilen)
	{
	case 1:	out[(*olen)++]=b32[in[0]>>3];
		out[(*olen)++]=b32[((in[0]<<2)&0x1f)];
		out[(*olen)++]='=';
		out[(*olen)++]='=';
		out[(*olen)++]='=';
		out[(*olen)++]='=';
		out[(*olen)++]='=';
		out[(*olen)++]='=';
		break;
	case 2:	out[(*olen)++]=b32[in[0]>>3];
		out[(*olen)++]=b32[((in[0]<<2)&0x1f)|(in[1]>>6)];
		out[(*olen)++]=b32[(in[1]>>1)&0x1f];
		out[(*olen)++]=b32[((in[1]<<4)&0x1f)];
		out[(*olen)++]='=';
		out[(*olen)++]='=';
		out[(*olen)++]='=';
		out[(*olen)++]='=';
		break;
	case 3:	out[(*olen)++]=b32[in[0]>>3];
		out[(*olen)++]=b32[((in[0]<<2)&0x1f)|(in[1]>>6)];
		out[(*olen)++]=b32[(in[1]>>1)&0x1f];
		out[(*olen)++]=b32[((in[1]<<4)&0x1f)|(in[2]>>4)];
		out[(*olen)++]=b32[((in[2]<<1)&0x1f)];
		out[(*olen)++]='=';
		out[(*olen)++]='=';
		out[(*olen)++]='=';
		break;
	case 4:	out[(*olen)++]=b32[in[0]>>3];
		out[(*olen)++]=b32[((in[0]<<2)&0x1f)|(in[1]>>6)];
		out[(*olen)++]=b32[(in[1]>>1)&0x1f];
		out[(*olen)++]=b32[((in[1]<<4)&0x1f)|(in[2]>>4)];
		out[(*olen)++]=b32[((in[2]<<1)&0x1f)|(in[3]>>7)];
		out[(*olen)++]=b32[(in[3]>>2)&0x1f];
		out[(*olen)++]=b32[((in[3]<<3)&0x1f)];
		out[(*olen)++]='=';
		break;
	}
	out[*olen]=0;
	return 0;
}

int neosc_util_base32_decode(char *in,int ilen,unsigned char *out,int *olen)
{
	int i;
	unsigned char n;
	unsigned char r=0;

	if(!in||ilen<0||(ilen&7)||!out||!olen)return -1;
	if(ilen)
	{
		if(in[ilen-1]=='=')ilen--;
		if(in[ilen-1]=='=')ilen--;
		if(in[ilen-1]=='=')ilen--;
		if(in[ilen-1]=='=')ilen--;
		if(in[ilen-1]=='=')ilen--;
		if(in[ilen-1]=='=')ilen--;
	}
	switch(ilen&7)
	{
	case 0:	if(*olen<(ilen>>3)*5)return -1;
		break;
	case 2:	if(*olen<(ilen>>3)*5+1)return -1;
		break;
	case 4:	if(*olen<(ilen>>3)*5+2)return -1;
		break;
	case 5:	if(*olen<(ilen>>3)*5+3)return -1;
		break;
	case 7:	if(*olen<(ilen>>3)*5+4)return -1;
		break;
	default:return -1;
	}

	for(i=0,*olen=0;ilen--;i=(i+1)&7,in++)
	{
		if(*in>='A'&&*in<='Z')n=*in-'A';
		else if(*in>='a'&&*in<='z')n=*in-'a';
		else if(*in>='2'&&*in<='7')n=*in-'2'+26;
		else return -1;

		switch(i)
		{
		case 0: out[*olen]=n<<3;
			break;
		case 1:	out[(*olen)++]|=n>>2;
			r=n<<6;
			break;
		case 2:	r|=(n<<1);
			break;
		case 3:	out[(*olen)++]=r|(n>>4);
			r=n<<4;
			break;
		case 4:	out[(*olen)++]=r|(n>>1);
			r=n<<7;
			break;
		case 5:	r|=n<<2;
			break;
		case 6:	out[(*olen)++]=r|(n>>3);
			r=n<<5;
			break;
		case 7:	out[(*olen)++]=r|n;
			break;
		}
	}
	return 0;
}

int neosc_util_qrurl(char *name,int otpmode,int shamode,int digits,
	unsigned int counter,unsigned char *secret,int slen,char *out,int olen)
{
	char *ptr;
	char bfr[512];
	char sectxt[64];
	int len=sizeof(sectxt);

	if(!name||!*name||strlen(name)>NEOSC_OATH_NAMELEN||
		(otpmode^(otpmode&1))||(shamode^(shamode&1))||digits<6||
		digits>8||!secret||slen!=
			(shamode?NEOSC_SHA256_SIZE:NEOSC_SHA1_SIZE)||!out)
		return -1;

	if(neosc_util_base32_encode(secret,slen,sectxt,&len))
		return -1;
	if(otpmode)strcpy(bfr,"otpauth://totp/");
	else strcpy(bfr,"otpauth://hotp/");
	for(ptr=bfr+15;*name;name++)switch(*name)
	{
	case '0'...'9':
	case 'A'...'Z':
	case 'a'...'z':
	case '-':
	case '_':
	case '.':
	case '~':
		*ptr++=*name;
		break;
	default:*ptr++='%';
		*ptr=(*name>>4)&0xf;
		if(*ptr<10)*ptr+++='0';
		else *ptr+++='a'-10;
		*ptr=*name&0xf;
		if(*ptr<10)*ptr+++='0';
		else *ptr+++='a'-10;
		break;
	}
	ptr+=sprintf(ptr,"?secret=%s",sectxt);
	memclear(sectxt,0,sizeof(sectxt));
	if(digits==7)strcat(ptr,"&digits=7");
	else if(digits==8)strcat(ptr,"&digits=8");
	if(shamode)strcat(ptr,"&algorithm=SHA256");
	if(!otpmode&&counter)sprintf(ptr+strlen(ptr),"&counter=%u",counter);
	if(strlen(bfr)>=olen)
	{
		memclear(bfr,0,sizeof(bfr));
		return -1;
	}
	strcpy(out,bfr);
	memclear(bfr,0,sizeof(bfr));
	return 0;
}
