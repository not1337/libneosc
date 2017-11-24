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

#include "libneosc.h"

static unsigned char sel_pgp[]=
{
	0x00,0xA4,0x04,0x00,0x06,0xd2,0x76,0x00,0x01,0x24,0x01
};

int neosc_pgp_select(void *ctx)
{
	int status;

	if(!ctx)return -1;

	if(neosc_pcsc_apdu(ctx,sel_pgp,sizeof(sel_pgp),NULL,NULL,&status)||
		status!=0x9000)return -1;

	return 0;
}
