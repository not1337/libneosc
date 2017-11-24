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
#include "libneosc.h"

static unsigned char sel_piv[]=
{
	0x00,0xA4,0x04,0x00,0x0B,0xA0,0x00,0x00,
	0x03,0x08,0x00,0x00,0x10,0x00,0x01,0x00
};

int neosc_piv_select(void *ctx)
{
	int status;
	unsigned char bfr[32];
	int len=sizeof(bfr);

	if(!ctx)return -1;

	if(neosc_pcsc_apdu(ctx,sel_piv,sizeof(sel_piv),bfr,&len,&status)||
		status!=0x9000||len<4)return -1;

	if(bfr[0]!=0x61||bfr[1]!=len-2)return -1;
	if(bfr[2]!=0x4f||bfr[3]>len-4||bfr[3]<6)return -1;
	if(memcmp(bfr+4,sel_piv+10,6))return -1;

	return 0;
}
