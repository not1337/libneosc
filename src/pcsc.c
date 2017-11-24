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

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <pcsclite.h>
#include <winscard.h>
#include "libneosc.h"

#define USB 0
#define NFC 1

/* workaround for yubikey 4 not showing serial in reader list */

#define YUBIKEY4_ID "Yubico Yubikey 4 "
#define U2F_ID      "U2F"

typedef struct
{
	SCARDCONTEXT card;
	SCARDHANDLE handle;
	int lock;
} CTX;

typedef struct
{
	char *name;
	int atrlen;
	unsigned char atr[MAX_ATR_SIZE];
} LIST;

/* Yubikey NEO v3.3.0 USB */

static unsigned char neo_atr1[]=
{
	0x3B,0xFC,0x13,0x00,0x00,0x81,0x31,0xFE,0x15,0x59,0x75,
	0x62,0x69,0x6B,0x65,0x79,0x4E,0x45,0x4F,0x72,0x33,0xE1
};

/* Yubikey NEO v3.3.0 NFC */

static unsigned char neo_atr2[]=
{
	0x3b,0x8c,0x80,0x01,0x59,0x75,0x62,0x69,0x6b,
	0x65,0x79,0x4e,0x45,0x4f,0x72,0x33,0x58
};

/* Yubikey 4 nano v4.3.5 USB */

static unsigned char yk4_atr1[]=
{
	0x3B,0xF8,0x13,0x00,0x00,0x81,0x31,0xFE,0x15,0x59,0x75,
	0x62,0x69,0x6B,0x65,0x79,0x34,0xD4
};

static struct
{
	unsigned char *atr;
	int len;
	int type;
} atrlist[]=
{
	{yk4_atr1,sizeof(yk4_atr1),USB},
	{neo_atr1,sizeof(neo_atr1),USB},
	{neo_atr2,sizeof(neo_atr2),NFC},
	{NULL,0,0}
};

static int init_pcsc(void **ctx)
{
	CTX *_ctx;

	if(!ctx||!(_ctx=malloc(sizeof(CTX))))return -1;
	memset(_ctx,0,sizeof(CTX));

	if(SCardEstablishContext(SCARD_SCOPE_USER,NULL,NULL,&_ctx->card)
		!=SCARD_S_SUCCESS)return -1;
	*ctx=_ctx;
	return 0;
}

static void fini_pcsc(void *ctx)
{
	CTX *_ctx=ctx;

	if(!ctx)return;
	SCardReleaseContext(_ctx->card);
	free(ctx);
}

static int connect_pcsc(void *ctx,char *name)
{
	CTX *_ctx=ctx;
	DWORD unused;

	if(!ctx||!name)return -1;
	if(SCardConnect(_ctx->card,name,SCARD_SHARE_SHARED,
		SCARD_PROTOCOL_T0|SCARD_PROTOCOL_T1,&_ctx->handle,&unused)!=
			SCARD_S_SUCCESS)return -1;
	return 0;
}

static void disconnect_pcsc(void *ctx)
{
	CTX *_ctx=ctx;

	SCardDisconnect(_ctx->handle,SCARD_LEAVE_CARD);
}

static int list_pcsc(void *ctx,LIST **readers,int *total)
{
	int i;
	int j;
	char *ptr;
	LIST *arr;
	CTX *_ctx=ctx;
	DWORD len=SCARD_AUTOALLOCATE;
	LPSTR *data;
	SCARD_READERSTATE state;

	if(!ctx||!readers)return -1;
	if(SCardListReaders(_ctx->card,NULL,(LPSTR)&data,&len)!=
		SCARD_S_SUCCESS)return -1;
	for(*total=0,ptr=(char *)data,i=0;i<len;i++)if(!ptr[i])(*total)++;
	if(!*total||!--(*total))
	{
		*readers=NULL;
		return 0;
	}
	if(!(*readers=malloc(*total*sizeof(LIST)+len)))
	{
		SCardFreeMemory(_ctx->handle,data);
		return -1;
	}
	ptr=((char *)(*readers))+*total*sizeof(LIST);
	memcpy(ptr,data,len);
	SCardFreeMemory(_ctx->handle,data);
	arr=*readers;
	arr[0].name=ptr;
	for(j=1,i=1;i<len&&j<*total;i++)if(!ptr[i])arr[j++].name=ptr+i+1;
	for(j=0;j<*total;j++)
	{
		arr[j].atrlen=0;
		state.szReader=arr[j].name;
		state.dwCurrentState=SCARD_STATE_UNAWARE;
		if(SCardGetStatusChange(_ctx->card,INFINITE,&state,1)!=
			SCARD_S_SUCCESS)continue;
		if(((state.dwEventState&0xffff)&
		   (SCARD_STATE_PRESENT|SCARD_STATE_EXCLUSIVE|SCARD_STATE_MUTE))
			!=SCARD_STATE_PRESENT)continue;
		if(!state.cbAtr)continue;
		arr[j].atrlen=state.cbAtr;
		memcpy(arr[j].atr,state.rgbAtr,arr[j].atrlen);
	}
	return 0;
}

static int pcsc_apdu(void *ctx,unsigned char *in,int ilen,unsigned char *out,
	int *olen)
{
	CTX *_ctx=ctx;
	DWORD len;
	DWORD unused;

	len=*olen;
	switch(SCardTransmit(_ctx->handle,SCARD_PCI_T1,in,ilen,NULL,out,&len))
	{
	case SCARD_W_RESET_CARD:
		if(SCardReconnect(_ctx->handle,SCARD_SHARE_SHARED,
			SCARD_PROTOCOL_T0|SCARD_PROTOCOL_T1,SCARD_LEAVE_CARD,
			&unused)!=SCARD_S_SUCCESS)return -1;
		if(_ctx->lock)if(SCardBeginTransaction(_ctx->card)!=
			SCARD_S_SUCCESS)return -1;
		len=*olen;
		if(SCardTransmit(_ctx->handle,SCARD_PCI_T1,in,ilen,NULL,out,
			&len)!=SCARD_S_SUCCESS)return -1;
	case SCARD_S_SUCCESS:
		*olen=len;
		return 0;

	default:return -1;
	}
}

int neosc_pcsc_apdu(void *ctx,unsigned char *in,int ilen,unsigned char *out,
	int *olen,int *status)
{
	unsigned char bfr[MAX_BUFFER_SIZE];
	int len=sizeof(bfr);

	if(!ctx||!in||!ilen)return -1;
	if(out&&!olen)return -1;
	if(pcsc_apdu(ctx,in,ilen,bfr,&len))return -1;
	if(len<2)return -1;
	if(status)
	{
		*status=bfr[len-2];
		*status<<=8;
		*status|=bfr[len-1];
	}
	len-=2;
	if(out)
	{
		if(*olen<len)return -1;
		*olen=len;
		memcpy(out,bfr,len);
	}
	return 0;
}

int neosc_pcsc_lock(void *ctx)
{
	CTX *_ctx=ctx;
	DWORD unused;

	if(_ctx->lock)return 0;
	switch(SCardBeginTransaction(_ctx->handle))
	{
	case SCARD_W_RESET_CARD:
		if(SCardReconnect(_ctx->handle,SCARD_SHARE_SHARED,
			SCARD_PROTOCOL_T0|SCARD_PROTOCOL_T1,SCARD_LEAVE_CARD,
			&unused)!=SCARD_S_SUCCESS)return -1;
		if(SCardBeginTransaction(_ctx->handle)!=SCARD_S_SUCCESS)
			return -1;
	case SCARD_S_SUCCESS:
		_ctx->lock=1;
		return 0;

	default:return -1;
	}
}

int neosc_pcsc_unlock(void *ctx)
{
	CTX *_ctx=ctx;
	DWORD unused;

	if(!_ctx->lock)return 0;
	switch(SCardEndTransaction(_ctx->handle,SCARD_LEAVE_CARD))
	{
	case SCARD_W_RESET_CARD:
		if(SCardReconnect(_ctx->handle,SCARD_SHARE_SHARED,
			SCARD_PROTOCOL_T0|SCARD_PROTOCOL_T1,SCARD_LEAVE_CARD,
			&unused)!=SCARD_S_SUCCESS)return -1;
	case SCARD_S_SUCCESS:
		_ctx->lock=0;
		return 0;

	default:return -1;
	}
}

int neosc_pcsc_open(void **ctx,int serial)
{
	int i;
	int j;
	int total;
	int devserial;
	LIST *list;
	char txt[20];

	if(serial<0&&serial!=NEOSC_USB_YUBIKEY&&serial!=NEOSC_NFC_YUBIKEY&&
		serial!=NEOSC_U2F_YUBIKEY4&&serial!=NEOSC_NOU2F_YUBIKEY4)
			return -1;
	if(!ctx)return -1;

	if(init_pcsc(ctx))goto err1;
	if(list_pcsc(*ctx,&list,&total)||!total)goto err2;
	if(serial==NEOSC_ANY_YUBIKEY)
	{
		for(i=0;i<total;i++)for(j=0;atrlist[j].atr;j++)
		    if(list[i].atrlen==atrlist[j].len)
			if(!memcmp(list[i].atr,atrlist[j].atr,atrlist[j].len))
		{
			if(connect_pcsc(*ctx,list[i].name))goto err3;
			free(list);
			return 0;
		}
	}
	else if(serial==NEOSC_USB_YUBIKEY)
	{
		for(i=0;i<total;i++)for(j=0;atrlist[j].atr;j++)
		    if(atrlist[j].type==USB)if(list[i].atrlen==atrlist[j].len)
			if(!memcmp(list[i].atr,atrlist[j].atr,atrlist[j].len))
			    if(!strchr(list[i].name,'(')&&
				!strchr(list[i].name,')'))
		{
			if(connect_pcsc(*ctx,list[i].name))goto err3;
			free(list);
			return 0;
		}
	}
	else if(serial==NEOSC_NFC_YUBIKEY)
	{
		for(i=0;i<total;i++)for(j=0;atrlist[j].atr;j++)
		    if(atrlist[j].type==NFC)if(list[i].atrlen==atrlist[j].len)
			if(!memcmp(list[i].atr,atrlist[j].atr,atrlist[j].len))
		{
			if(connect_pcsc(*ctx,list[i].name))goto err3;
			free(list);
			return 0;
		}
	}
	else if(serial==NEOSC_U2F_YUBIKEY4)
	{
		for(i=0;i<total;i++)for(j=0;atrlist[j].atr;j++)
		    if(atrlist[j].type==USB)if(list[i].atrlen==atrlist[j].len)
			if(!memcmp(list[i].atr,atrlist[j].atr,atrlist[j].len))
			    if(strstr(list[i].name,YUBIKEY4_ID))
				if(strstr(list[i].name,U2F_ID))
		{
			if(connect_pcsc(*ctx,list[i].name))goto err3;
			free(list);
			return 0;
		}
	}
	else if(serial==NEOSC_NOU2F_YUBIKEY4)
	{
		for(i=0;i<total;i++)for(j=0;atrlist[j].atr;j++)
		    if(atrlist[j].type==USB)if(list[i].atrlen==atrlist[j].len)
			if(!memcmp(list[i].atr,atrlist[j].atr,atrlist[j].len))
			    if(strstr(list[i].name,YUBIKEY4_ID))
				if(!strstr(list[i].name,U2F_ID))
		{
			if(connect_pcsc(*ctx,list[i].name))goto err3;
			free(list);
			return 0;
		}
	}
	else
	{
		snprintf(txt,sizeof(txt),"(%010d)",serial);

		for(i=0;i<total;i++)for(j=0;atrlist[j].atr;j++)
		    if(atrlist[j].type==USB)if(list[i].atrlen==atrlist[j].len)
			if(!memcmp(list[i].atr,atrlist[j].atr,atrlist[j].len))
			    if(strstr(list[i].name,txt))
		{
			if(connect_pcsc(*ctx,list[i].name))goto err3;
			free(list);
			return 0;
		}

		for(i=0;i<total;i++)for(j=0;atrlist[j].atr;j++)
		    if(atrlist[j].type==NFC)if(list[i].atrlen==atrlist[j].len)
			if(!memcmp(list[i].atr,atrlist[j].atr,atrlist[j].len))
		{
			if(connect_pcsc(*ctx,list[i].name))continue;
			if(neosc_pcsc_lock(*ctx))
			{
				disconnect_pcsc(ctx);
				goto err3;
			}
			if(neosc_neo_select(*ctx,NULL))
			{
				neosc_pcsc_unlock(*ctx);
				disconnect_pcsc(*ctx);
				goto err3;
			}
			if(neosc_neo_read_serial(*ctx,&devserial))
			{
				neosc_pcsc_unlock(*ctx);
				disconnect_pcsc(*ctx);
				continue;
			}
			if(neosc_pcsc_unlock(*ctx))
			{
				disconnect_pcsc(*ctx);
				goto err3;
			}
			if(devserial!=serial)
			{
				disconnect_pcsc(*ctx);
				continue;
			}
			free(list);
			return 0;
		}
	}

err3:	free(list);
err2:	fini_pcsc(*ctx);
err1:	return -1;
}

void neosc_pcsc_close(void *ctx)
{
	disconnect_pcsc(ctx);
	fini_pcsc(ctx);
}
