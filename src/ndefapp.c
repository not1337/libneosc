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
#include "libneosc.h"

static unsigned char sel_ndef[]=
{
	0x00,0xA4,0x04,0x00,0x07,0xD2,0x76,0x00,0x00,0x85,0x01,0x01,0x00
};

static unsigned char sel_cc_file[]=
{
	0x00,0xA4,0x00,0x0C,0x02,0xE1,0x03
};

static unsigned char sel_ndef_file[]=
{
	0x00,0xA4,0x00,0x0C,0x02,0xE1,0x04
};

static unsigned char read_file[]=
{
	0x00,0xB0,0x00,0x00,0x00
};

int neosc_ndef_select(void *ctx)
{
	int status;

	if(!ctx)return -1;

	if(neosc_pcsc_apdu(ctx,sel_ndef,sizeof(sel_ndef),NULL,NULL,&status)||
		status!=0x9000)return -1;
	return 0;
}

int neosc_ndef_read_cc(void *ctx,NEOSC_NDEF_CC *data)
{
	int status;
	unsigned char bfr[NEOSC_APDU_BUFFER];
	int len=sizeof(bfr);

	if(!ctx||!data)return -1;

	if(neosc_pcsc_apdu(ctx,sel_cc_file,sizeof(sel_cc_file),NULL,NULL,
		&status)||status!=0x9000)return -1;
	if(neosc_pcsc_apdu(ctx,read_file,sizeof(read_file),bfr,&len,&status)||
		status!=0x9000||len<15)return -1;
	if(bfr[0]!=0x00||bfr[1]!=0x0f||bfr[7]!=0x04||bfr[8]!=0x06)return -1;
	data->version=bfr[2];
	data->mle=bfr[3];
	data->mle<<=8;
	data->mle|=bfr[4];
	data->mlc=bfr[5];
	data->mlc<<=8;
	data->mlc|=bfr[6];
	data->fileid=bfr[9];
	data->fileid<<=8;
	data->fileid|=bfr[10];
	data->ndef_max=bfr[11];
	data->ndef_max<<=8;
	data->ndef_max|=bfr[12];
	data->rcond=bfr[13];
	data->wcond=bfr[14];
	return 0;
}

int neosc_ndef_read_ndef(void *ctx,NEOSC_NDEF *data)
{
	int status;
	unsigned char bfr[NEOSC_APDU_BUFFER];
	int len=sizeof(bfr);
	int ulen;
	char *uri;

	if(!ctx||!data)return -1;

	if(neosc_pcsc_apdu(ctx,sel_ndef_file,sizeof(sel_ndef_file),NULL,NULL,
		&status)||status!=0x9000)return -1;
	if(neosc_pcsc_apdu(ctx,read_file,sizeof(read_file),bfr,&len,&status)||
		status!=0x9000||len<5)return -1;
	status=bfr[0];
	status<<=8;
	status|=bfr[1];
	if(status!=len-2)return -1;
	switch(bfr[2])
	{
	case 0xd0:
		if(bfr[3]||bfr[4])return -1;
		data->language[0]=0;
		data->payload[0]=0;
		return 0;
	case 0xd1:
		if(len<6)return -1;
		if(bfr[3]!=0x01)return -1;
		if(bfr[4]!=len-6)return -1;
		break;
	default:return -1;
	}
	switch(bfr[5])
	{
	case 0x54:
		if(len<7||len-7<(bfr[6]&0x7f))return -1;
		data->type=NEOSC_NDEF_TEXT;
		memcpy(data->language,bfr+7,(bfr[6]&0x7f));
		data->language[bfr[6]&0x7f]=0;
		memcpy(data->payload,bfr+(bfr[6]&0x7f)+7,len-(bfr[6]&0x7f)-7);
		data->payload[len-(bfr[6]&0x7f)-7]=0;
		break;
	case 0x55:
		uri=neosc_util_id2uri(bfr[6]);
		ulen=strlen(uri);
		if(len-7+ulen>=sizeof(data->payload))return -1;
		data->type=NEOSC_NDEF_URL;
		data->language[0]=0;
		memcpy(data->payload,uri,ulen);
		memcpy(data->payload+ulen,bfr+7,len-7);
		data->payload[len+ulen-7]=0;
		break;
	default:return -1;
	}
	return 0;
}
