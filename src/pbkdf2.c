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

#include "libneosc.h"

void neosc_pbkdf2(char *pass,unsigned char *salt,int slen,int iterations,
	unsigned char *out,int olen)
{
        int i;
	int j;
	int k;
        unsigned char bfr[4];
	NEOSC_SHA1(tmp1);
        NEOSC_SHA1(tmp2);
	NEOSC_SHA1HMDATA hmdata;
	NEOSC_SHA1DATA data;

	for(k=0;pass[k];k++);
	neosc_sha1hmkey((unsigned char *)pass,k,&hmdata);

	for(i=1;olen;i++,out+=j,olen-=j)
	{
        	bfr[0]=(unsigned char)(i>>24);
        	bfr[1]=(unsigned char)(i>>16);
        	bfr[2]=(unsigned char)(i>>8);
        	bfr[3]=(unsigned char)i;

		neosc_sha1hminit(&data,&hmdata);
		neosc_sha1hmnext(salt,slen,&data);
		neosc_sha1hmnext(bfr,4,&data);
		neosc_sha1hmend(tmp1,&data,&hmdata);

		for(k=0;k<NEOSC_SHA1_SIZE;k++)tmp2[k]=tmp1[k];

		for(k=1;k<iterations;k++)
		{
			neosc_sha1hmac(tmp1,NEOSC_SHA1_SIZE,tmp1,&hmdata);
			for(j=0;j<NEOSC_SHA1_SIZE;j++)tmp2[j]^=tmp1[j];
		}

		j=olen>NEOSC_SHA1_SIZE?NEOSC_SHA1_SIZE:olen;
		for(k=0;k<j;k++)out[k]=tmp2[k];
	}

	for(k=0;k<sizeof(hmdata);k++)((unsigned char *)&hmdata)[k]=0;
}
