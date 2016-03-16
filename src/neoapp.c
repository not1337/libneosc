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
#include <unistd.h>
#include "libneosc.h"

#define memclear(a,b,c) \
    do { memset(a,b,c); *(volatile char*)(a)=*(volatile char*)(a); } while(0)

static unsigned char sel_neo[]=
{
	0x00,0xA4,0x04,0x00,0x07,0xA0,0x00,0x00,0x05,0x27,0x20,0x01
};

static unsigned char set_config[]=
{
	0x00,0x01,0x01,0x00
};

static unsigned char set_config2[]=
{
	0x00,0x01,0x03,0x00
};

static unsigned char upd_config[]=
{
	0x00,0x01,0x04,0x00
};

static unsigned char upd_config2[]=
{
	0x00,0x01,0x05,0x00
};

static unsigned char do_swap[]=
{
	0x00,0x01,0x06,0x00
};

static unsigned char set_ndef[]=
{
	0x00,0x01,0x08,0x00
};

static unsigned char set_ndef2[]=
{
	0x00,0x01,0x09,0x00
};

static unsigned char get_serial[]=
{
	0x00,0x01,0x10,0x00
};

static unsigned char set_mode[]=
{
	0x00,0x01,0x11,0x00
};

static unsigned char set_scanmap[]=
{
	0x00,0x01,0x12,0x00
};

static unsigned char get_otp1[]=
{
	0x00,0x01,0x20,0x00
};

static unsigned char get_otp2[]=
{
	0x00,0x01,0x28,0x00
};

static unsigned char get_hmac1[]=
{
	0x00,0x01,0x30,0x00
};

static unsigned char get_hmac2[]=
{
	0x00,0x01,0x38,0x00
};

static unsigned char get_yubiotp1[]=
{
	0x00,0x02,0x00,0x00
};

static unsigned char get_yubiotp2[]=
{
	0x00,0x02,0x01,0x00
};

static unsigned char get_status[]=
{
	0x00,0x03,0x00,0x00
};

static unsigned char get_ndef[]=
{
	0x00,0x04,0x00,0x00
};

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

int neosc_neo_select(void *ctx,NEOSC_NEO_INFO *info)
{
	int status;
	unsigned char bfr[14];
	int len=sizeof(bfr);

	if(!ctx)return -1;

	if(neosc_pcsc_apdu(ctx,sel_neo,sizeof(sel_neo),bfr,&len,&status)||
		status!=0x9000||len<10)return -1;

	if(info)
	{
		info->major=bfr[0];
		info->minor=bfr[1];
		info->build=bfr[2];
		info->pgmseq=bfr[3];
		info->touchlevel=bfr[5];
		info->touchlevel<<=8;
		info->touchlevel|=bfr[4];
		info->mode=bfr[6];
		info->crtimeout=bfr[7];
		info->autoejecttime=bfr[9];
		info->autoejecttime<<=8;
		info->autoejecttime|=bfr[8];
		info->config1=(info->touchlevel&0x01)?1:0;
		info->config2=(info->touchlevel&0x02)?1:0;
		info->touch1=(info->touchlevel&0x04)?1:0;
		info->touch2=(info->touchlevel&0x08)?1:0;
		info->ledinv=(info->touchlevel&0x10)?1:0;
		info->touchlevel&=~0x1f;
	}
	return 0;
}

int neosc_neo_read_serial(void *ctx,int *serial)
{
	int status;
	unsigned char bfr[4];
	int len=sizeof(bfr);

	if(neosc_pcsc_apdu(ctx,get_serial,sizeof(get_serial),bfr,&len,
		&status)||status!=0x9000||len!=4)return -1;
	*serial=bfr[0];
	*serial<<=8;
	*serial|=bfr[1];
	*serial<<=8;
	*serial|=bfr[2];
	*serial<<=8;
	*serial|=bfr[3];
	return 0;
}

int neosc_neo_read_hmac(void *ctx,int slot,unsigned char *in,int ilen,
	unsigned char *out,int olen)
{
	int r=0;
	int status;
	unsigned char bfr[sizeof(get_hmac1)+65];

	if(!ctx||!in||ilen<1||ilen>64||slot<0||slot>1||!out||
		olen<NEOSC_SHA1_SIZE)return -1;

	memcpy(bfr,slot?get_hmac2:get_hmac1,sizeof(get_hmac1));
	bfr[sizeof(get_hmac1)]=(unsigned char)ilen;
	memcpy(bfr+sizeof(get_hmac1)+1,in,ilen);
	if(neosc_pcsc_apdu(ctx,bfr,sizeof(get_hmac1)+ilen+1,out,&olen,&status)||
		status!=0x9000||olen!=NEOSC_SHA1_SIZE)r=-1;
	memclear(bfr,0,sizeof(bfr));
	return r;
}

int neosc_neo_read_otp(void *ctx,int slot,unsigned char *in,int ilen,
	unsigned char *out,int olen)
{
	int r=0;
	int status;
	unsigned char bfr[sizeof(get_otp1)+65];

	if(!ctx||!in||ilen!=6||slot<0||slot>1||!out||olen<16)return -1;

	memcpy(bfr,slot?get_otp2:get_otp1,sizeof(get_otp1));
	bfr[sizeof(get_otp1)]=(unsigned char)ilen;
	memcpy(bfr+sizeof(get_otp1)+1,in,ilen);
	if(neosc_pcsc_apdu(ctx,bfr,sizeof(get_otp1)+ilen+1,out,&olen,&status)||
		status!=0x9000||olen!=16)r=-1;
	memclear(bfr,0,sizeof(bfr));
	return r;
}

int neosc_neo_read_status(void *ctx,NEOSC_STATUS *state)
{
	int status;
	unsigned char bfr[6];
	int len=sizeof(bfr);

	if(!ctx||!state)return -1;

	if(neosc_pcsc_apdu(ctx,get_status,sizeof(get_status),bfr,&len,&status)||
		status!=0x9000||len!=6)return -1;
	state->major=bfr[0];
	state->minor=bfr[1];
	state->build=bfr[2];
	state->pgmseq=bfr[3];
	state->touchlevel=bfr[5];
	state->touchlevel<<=8;
	state->touchlevel|=bfr[4];
	state->config1=(state->touchlevel&0x01)?1:0;
	state->config2=(state->touchlevel&0x02)?1:0;
	state->touch1=(state->touchlevel&0x04)?1:0;
	state->touch2=(state->touchlevel&0x08)?1:0;
	state->ledinv=(state->touchlevel&0x10)?1:0;
	state->touchlevel&=~0x1f;
	return 0;
}

int neosc_neo_read_ndef(void *ctx,NEOSC_NDEF *data)
{
	int status;
	unsigned char bfr[NEOSC_APDU_BUFFER];
	int len=sizeof(bfr);
	int ulen;
	char *uri;

	if(!ctx||!data)return -1;

	if(neosc_pcsc_apdu(ctx,get_ndef,sizeof(get_ndef),bfr,&len,&status)||
		status!=0x9000||len<2)return -1;
	switch(bfr[0])
	{
	case 0x54:
		if(len-2<(bfr[1]&0x7f))return -1;
		data->type=NEOSC_NDEF_TEXT;
		memcpy(data->language,bfr+2,(bfr[1]&0x7f));
		data->language[bfr[1]&0x7f]=0;
		memcpy(data->payload,bfr+(bfr[1]&0x7f)+2,len-(bfr[1]&0x7f)-2);
		data->payload[len-(bfr[1]&0x7f)-2]=0;
		break;
	case 0x55:
		uri=neosc_util_id2uri(bfr[1]);
		ulen=strlen(uri);
		if(len-2+ulen>=sizeof(data->payload))return -1;
		data->type=NEOSC_NDEF_URL;
		data->language[0]=0;
		memcpy(data->payload,uri,ulen);
		memcpy(data->payload+ulen,bfr+2,len-2);
		data->payload[len+ulen-2]=0;
		break;
	default:memclear(bfr,0,sizeof(bfr));
		return -1;
	}
	memclear(bfr,0,sizeof(bfr));
	return 0;
}

int neosc_neo_read_yubiotp(void *ctx,int slot,char *out,int olen)
{
	int status;

	if(!ctx||slot<0||slot>1||!out||olen<45)return -1;

	if(neosc_pcsc_apdu(ctx,slot?get_yubiotp2:get_yubiotp1,
		sizeof(get_yubiotp1),(unsigned char *)out,&olen,&status)||
		status!=0x9000||(olen!=44&&olen!=45))return -1;
	out[44]=0;
	return 0;
}

int neosc_neo_write_ndef(void *ctx,int slot,char *url,char *txt,char *lang,
	unsigned char *code,int codelen)
{
	int r=0;
	int status;
	int len;
	int id;
	int seq;
	int retry=1;
	NEOSC_STATUS state;
	unsigned char bfr[sizeof(set_ndef)+63];

	if(!ctx||(slot^(slot&1)))return -1;
	if(!url&&!txt)return -1;
	if(url&&txt)return -1;
	if(txt&&!lang)return -1;
	if(code&&codelen!=6)return -1;

repeat:	if(neosc_neo_read_status(ctx,&state))
	{
		memclear(bfr,0,sizeof(bfr));
		return -1;
	}
	seq=state.pgmseq;

	memcpy(bfr,slot?set_ndef2:set_ndef,sizeof(set_ndef));
	bfr[sizeof(set_ndef)]=62;
	memset(bfr+sizeof(set_ndef)+1,0,62);

	if(url)
	{
		id=neosc_util_uri2id(url);
		url+=strlen(neosc_util_id2uri(id));
		if((len=strlen(url))>53)return -1;
		bfr[sizeof(set_ndef)+1]=(unsigned char)(len+1);
		bfr[sizeof(set_ndef)+2]=0x55;
		bfr[sizeof(set_ndef)+3]=(unsigned char)id;
		memcpy(bfr+sizeof(set_ndef)+4,url,len);
	}
	else
	{
		len=strlen(txt);
		id=strlen(lang);
		if(len+id>53)return -1;
		bfr[sizeof(set_ndef)+1]=(unsigned char)(len+id+1);
		bfr[sizeof(set_ndef)+2]=0x54;
		bfr[sizeof(set_ndef)+3]=(unsigned char)id;
		memcpy(bfr+sizeof(set_ndef)+4,lang,id);
		memcpy(bfr+sizeof(set_ndef)+4+id,txt,len);
	}
	if(code)memcpy(bfr+sizeof(set_ndef)+57,code,6);

	if(neosc_pcsc_apdu(ctx,bfr,sizeof(bfr),NULL,NULL,&status)||
		status!=0x9000)r=-1;
	else if(neosc_neo_read_status(ctx,&state))r=-1;
	else if(seq==state.pgmseq)
	{
		if(retry--)
		{
			usleep(250000);
			goto repeat;
		}
		r=-1;
	}

	memclear(bfr,0,sizeof(bfr));
	return r;
}

int neosc_neo_write_scanmap(void *ctx,unsigned char *map,int maplen)
{
	int r=0;
	int status;
	int seq;
	int retry=1;
	NEOSC_STATUS state;
	unsigned char bfr[sizeof(set_scanmap)+46];

	if(!ctx||(map&&maplen!=45))return -1;

repeat:	if(neosc_neo_read_status(ctx,&state))
	{
		memclear(bfr,0,sizeof(bfr));
		return -1;
	}
	seq=state.pgmseq;

	memcpy(bfr,set_scanmap,sizeof(set_scanmap));
	bfr[sizeof(set_scanmap)]=45;
	if(!map)memset(bfr+sizeof(set_scanmap)+1,0,45);
	else memcpy(bfr+sizeof(set_scanmap)+1,map,45);

	if(neosc_pcsc_apdu(ctx,bfr,sizeof(bfr),NULL,NULL,&status)||
		status!=0x9000)r=-1;
	else if(neosc_neo_read_status(ctx,&state))r=-1;
	else if(seq==state.pgmseq)
	{
		if(retry--)
		{
			usleep(250000);
			goto repeat;
		}
		r=-1;
	}

	memclear(bfr,0,sizeof(bfr));
	return r;
}

int neosc_neo_setmode(void *ctx,int mode,int crtimeout,int autoejecttime)
{
	int r=0;
	int status;
	int seq;
	int retry=1;
	NEOSC_STATUS state;
	unsigned char bfr[sizeof(set_mode)+5];

	if(!ctx||(mode&~0x87)||(mode&0x07)==0x07||crtimeout<0||crtimeout>255||
		autoejecttime<0||autoejecttime>65535)return -1;

repeat:	if(neosc_neo_read_status(ctx,&state))
	{
		memclear(bfr,0,sizeof(bfr));
		return -1;
	}
	seq=state.pgmseq;

	memcpy(bfr,set_mode,sizeof(set_mode));
	bfr[sizeof(set_mode)]=0x04;
	bfr[sizeof(set_mode)+1]=(unsigned char)mode;
	bfr[sizeof(set_mode)+2]=(unsigned char)crtimeout;
	bfr[sizeof(set_mode)+3]=(unsigned char)autoejecttime;
	bfr[sizeof(set_mode)+4]=(unsigned char)(autoejecttime>>8);

	if(neosc_pcsc_apdu(ctx,bfr,sizeof(bfr),NULL,NULL,&status)||
		status!=0x9000)r=-1;
	else if(neosc_neo_read_status(ctx,&state))r=-1;
	else if(seq==state.pgmseq)
	{
		if(retry--)
		{
			usleep(250000);
			goto repeat;
		}
		r=-1;
	}

	memclear(bfr,0,sizeof(bfr));
	return r;
}

int neosc_neo_reset(void *ctx,int slot)
{
	int r=0;
	int status;
	int seq;
	int retry=1;
	NEOSC_STATUS state;
	unsigned char bfr[sizeof(set_config)+59];

	if(!ctx||(slot^(slot&1)))return -1;

repeat:	if(neosc_neo_read_status(ctx,&state))return -1;
	seq=state.pgmseq;

	memcpy(bfr,slot?set_config2:set_config,sizeof(set_config));
	bfr[sizeof(set_config)]=58;
	memset(bfr+sizeof(set_config)+1,0,58);

	if(neosc_pcsc_apdu(ctx,bfr,sizeof(bfr),NULL,NULL,&status)||
		status!=0x9000)r=-1;
	else if(neosc_neo_read_status(ctx,&state))r=-1;
	else if(!state.config1&&!state.config2&&!state.pgmseq);
	else if(seq==state.pgmseq)
	{
		if(retry--)
		{
			usleep(250000);
			goto repeat;
		}
		r=-1;
	}

	return r;
}

int neosc_neo_config(void *ctx,unsigned char *apdu4,int tktflags,int cfgflags,
	int extflags,unsigned char *fixeddata,int fixedlen,
	unsigned char *uidpart,int uidlen,unsigned char *aesdata,int aeslen,
	unsigned char *newcode,int newlen,unsigned char *code,int codelen)
{
	unsigned short crc;
	int r=0;
	int status;
	int seq;
	int retry=1;
	NEOSC_STATUS state;
	unsigned char bfr[63];

	if(!ctx||!apdu4)return -1;
	if(code&&codelen!=6)return -1;
	if(newcode&&newlen!=6)return -1;
	if(fixeddata)if(fixedlen<0||fixedlen>16)return -1;
	if(uidpart&&uidlen!=4&&uidlen!=6)return -1;
	if(aesdata&&aeslen!=16)return -1;

repeat:	if(neosc_neo_read_status(ctx,&state))
	{
		memclear(bfr,0,sizeof(bfr));
		return -1;
	}
	seq=state.pgmseq;

	memcpy(bfr,apdu4,4);
	bfr[4]=58;
	memset(bfr+5,0,58);

	if(uidpart)memcpy(bfr+21,uidpart,uidlen);
	if(aesdata)memcpy(bfr+27,aesdata,16);
	if(newcode)memcpy(bfr+43,newcode,6);
	bfr[50]=(unsigned char)extflags;
	bfr[51]=(unsigned char)tktflags;
	bfr[52]=(unsigned char)cfgflags;
	crc=~crc16(bfr+5,50);
	bfr[55]=(unsigned char)crc;
	bfr[56]=(unsigned char)(crc>>8);
	if(code)memcpy(bfr+57,code,6);

	if(neosc_pcsc_apdu(ctx,bfr,sizeof(bfr),NULL,NULL,&status)||
		status!=0x9000)r=-1;
	else if(neosc_neo_read_status(ctx,&state))r=-1;
	else if(seq==state.pgmseq)
	{
		if(retry--)
		{
			usleep(250000);
			goto repeat;
		}
		r=-1;
	}

	memclear(bfr,0,sizeof(bfr));
	return r;
}

int neosc_neo_swap(void *ctx,unsigned char *newcode,int newlen,
	unsigned char *code,int codelen)
{
	return neosc_neo_config(ctx,do_swap,0,0,0,NULL,0,NULL,0,NULL,0,
		newcode,newlen,code,codelen);
}

int neosc_neo_update(void *ctx,int slot,int tktflags,int cfgflags,int extflags,
	unsigned char *newcode,int newlen,unsigned char *code,int codelen)
{
	if(slot^(slot&1))return -1;
	if((tktflags&~0x3f)||(cfgflags&~0x0c)||(extflags&~0xff))return -1;
	if((extflags&0x60)==0x40)return -1;

	return neosc_neo_config(ctx,slot?upd_config2:upd_config,tktflags,
		cfgflags,extflags,NULL,0,NULL,0,NULL,0,newcode,newlen,code,
		codelen);
}

int neosc_neo_hmac(void *ctx,int slot,unsigned char *aesdata,int aeslen,
	int tktflags,int cfgflags,int extflags,unsigned char *newcode,
	int newlen,unsigned char *code,int codelen)
{
	if((slot^(slot&1))||!aesdata||aeslen!=20||(tktflags&~0x80)||
		(cfgflags&~0x0c)||(extflags&~0xff))return -1;
	if((extflags&0x60)==0x40)return -1;

	return neosc_neo_config(ctx,slot?set_config2:set_config,tktflags|0x40,
		cfgflags|0x22,extflags,NULL,0,aesdata+16,4,aesdata,16,
		newcode,newlen,code,codelen);
}

int neosc_neo_otp(void *ctx,int slot,unsigned char *privid,int privlen,
	unsigned char *aesdata,int aeslen,int tktflags,int cfgflags,
	int extflags,unsigned char *newcode,int newlen,unsigned char *code,
	int codelen)
{
	if((slot^(slot&1))||!aesdata||aeslen!=16||(tktflags&~0x80)||
		(cfgflags&~0x08)||(extflags&~0xff))return -1;
	if((extflags&0x60)==0x40)return -1;
	if(privid&&privlen!=6)return -1;

	return neosc_neo_config(ctx,slot?set_config2:set_config,tktflags|0x40,
		cfgflags|0x20,extflags,NULL,0,privid,6,aesdata,16,
		newcode,newlen,code,codelen);
}

int neosc_neo_hotp(void *ctx,int slot,int omp,int tt,int mui,int imf,
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

	r=neosc_neo_config(ctx,slot?set_config2:set_config,tktflags|0x40,
		cfgflags,extflags,fixedlen?fixeddata:NULL,fixedlen,uidpart,6,
		aesdata,16,newcode,newlen,code,codelen);

	memclear(uidpart,0,6);
	memclear(fixeddata,0,6);
	return r;
}

int neosc_neo_yubiotp(void *ctx,int slot,unsigned char *pubid,int publen,
	unsigned char *privid,int privlen,unsigned char *aesdata,int aeslen,
	int tktflags,int cfgflags,int extflags,unsigned char *newcode,
	int newlen,unsigned char *code,int codelen)
{
	if((slot^(slot&1))||!aesdata||aeslen!=16||(tktflags&~0xbf)||
		(cfgflags&~0x0d)||(extflags&~0xff))return -1;
	if((extflags&0x60)==0x40)return -1;
	if(privid&&privlen!=6)return -1;

	return neosc_neo_config(ctx,slot?set_config2:set_config,tktflags,
		cfgflags,extflags,pubid,publen,privid,privlen,aesdata,16,
		newcode,newlen,code,codelen);
}

int neosc_neo_passwd(void *ctx,int slot,unsigned char *pubid,int publen,
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

	return neosc_neo_config(ctx,slot?set_config2:set_config,tktflags,
		cfgflags|0x20,extflags,pubid,publen,privid,privlen,aesdata,16,
		newcode,newlen,code,codelen);
}
