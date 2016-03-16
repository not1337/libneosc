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

static void sha1block(unsigned int *sha1,unsigned char *data)
{
	register unsigned int a;
	register unsigned int b;
	register unsigned int c;
	register unsigned int d;
	register unsigned int e;
	unsigned int w[16];

	a=data[0];
	a<<=8;
	a+=data[1];
	a<<=8;
	a+=data[2];
	a<<=8;
	w[0]=a+data[3];

	a=data[4];
	a<<=8;
	a+=data[5];
	a<<=8;
	a+=data[6];
	a<<=8;
	w[1]=a+data[7];

	a=data[8];
	a<<=8;
	a+=data[9];
	a<<=8;
	a+=data[10];
	a<<=8;
	w[2]=a+data[11];

	a=data[12];
	a<<=8;
	a+=data[13];
	a<<=8;
	a+=data[14];
	a<<=8;
	w[3]=a+data[15];

	a=data[16];
	a<<=8;
	a+=data[17];
	a<<=8;
	a+=data[18];
	a<<=8;
	w[4]=a+data[19];

	a=data[20];
	a<<=8;
	a+=data[21];
	a<<=8;
	a+=data[22];
	a<<=8;
	w[5]=a+data[23];

	a=data[24];
	a<<=8;
	a+=data[25];
	a<<=8;
	a+=data[26];
	a<<=8;
	w[6]=a+data[27];

	a=data[28];
	a<<=8;
	a+=data[29];
	a<<=8;
	a+=data[30];
	a<<=8;
	w[7]=a+data[31];

	a=data[32];
	a<<=8;
	a+=data[33];
	a<<=8;
	a+=data[34];
	a<<=8;
	w[8]=a+data[35];

	a=data[36];
	a<<=8;
	a+=data[37];
	a<<=8;
	a+=data[38];
	a<<=8;
	w[9]=a+data[39];

	a=data[40];
	a<<=8;
	a+=data[41];
	a<<=8;
	a+=data[42];
	a<<=8;
	w[10]=a+data[43];

	a=data[44];
	a<<=8;
	a+=data[45];
	a<<=8;
	a+=data[46];
	a<<=8;
	w[11]=a+data[47];

	a=data[48];
	a<<=8;
	a+=data[49];
	a<<=8;
	a+=data[50];
	a<<=8;
	w[12]=a+data[51];

	a=data[52];
	a<<=8;
	a+=data[53];
	a<<=8;
	a+=data[54];
	a<<=8;
	w[13]=a+data[55];

	a=data[56];
	a<<=8;
	a+=data[57];
	a<<=8;
	a+=data[58];
	a<<=8;
	w[14]=a+data[59];

	a=data[60];
	a<<=8;
	a+=data[61];
	a<<=8;
	a+=data[62];
	a<<=8;
	w[15]=a+data[63];

	a=sha1[0];
	b=sha1[1];
	c=sha1[2];
	d=sha1[3];
	e=sha1[4];

	e+=w[0];
	e+=0x5A827999;
	e+=(a<<5)|(a>>27);
	e+=((c^d)&b)^d;
	b=(b<<30)|(b>>2);

	d+=w[1];
	d+=0x5A827999;
	d+=(e<<5)|(e>>27);
	d+=((b^c)&a)^c;
	a=(a<<30)|(a>>2);

	c+=w[2];
	c+=0x5A827999;
	c+=(d<<5)|(d>>27);
	c+=((a^b)&e)^b;
	e=(e<<30)|(e>>2);

	b+=w[3];
	b+=0x5A827999;
	b+=(c<<5)|(c>>27);
	b+=((e^a)&d)^a;
	d=(d<<30)|(d>>2);

	a+=w[4];
	a+=0x5A827999;
	a+=(b<<5)|(b>>27);
	a+=((d^e)&c)^e;
	c=(c<<30)|(c>>2);

	e+=w[5];
	e+=0x5A827999;
	e+=(a<<5)|(a>>27);
	e+=((c^d)&b)^d;
	b=(b<<30)|(b>>2);

	d+=w[6];
	d+=0x5A827999;
	d+=(e<<5)|(e>>27);
	d+=((b^c)&a)^c;
	a=(a<<30)|(a>>2);

	c+=w[7];
	c+=0x5A827999;
	c+=(d<<5)|(d>>27);
	c+=((a^b)&e)^b;
	e=(e<<30)|(e>>2);

	b+=w[8];
	b+=0x5A827999;
	b+=(c<<5)|(c>>27);
	b+=((e^a)&d)^a;
	d=(d<<30)|(d>>2);

	a+=w[9];
	a+=0x5A827999;
	a+=(b<<5)|(b>>27);
	a+=((d^e)&c)^e;
	c=(c<<30)|(c>>2);

	e+=w[10];
	e+=0x5A827999;
	e+=(a<<5)|(a>>27);
	e+=((c^d)&b)^d;
	b=(b<<30)|(b>>2);

	d+=w[11];
	d+=0x5A827999;
	d+=(e<<5)|(e>>27);
	d+=((b^c)&a)^c;
	a=(a<<30)|(a>>2);

	c+=w[12];
	c+=0x5A827999;
	c+=(d<<5)|(d>>27);
	c+=((a^b)&e)^b;
	e=(e<<30)|(e>>2);

	b+=w[13];
	b+=0x5A827999;
	b+=(c<<5)|(c>>27);
	b+=((e^a)&d)^a;
	d=(d<<30)|(d>>2);

	a+=w[14];
	a+=0x5A827999;
	a+=(b<<5)|(b>>27);
	a+=((d^e)&c)^e;
	c=(c<<30)|(c>>2);

	e+=w[15];
	e+=0x5A827999;
	e+=(a<<5)|(a>>27);
	e+=((c^d)&b)^d;
	b=(b<<30)|(b>>2);

	w[0]^=w[13]^w[8]^w[2];
	w[0]=(w[0]<<1)|(w[0]>>31);
	d+=w[0];
	d+=0x5A827999;
	d+=(e<<5)|(e>>27);
	d+=((b^c)&a)^c;
	a=(a<<30)|(a>>2);

	w[1]^=w[14]^w[9]^w[3];
	w[1]=(w[1]<<1)|(w[1]>>31);
	c+=w[1];
	c+=0x5A827999;
	c+=(d<<5)|(d>>27);
	c+=((a^b)&e)^b;
	e=(e<<30)|(e>>2);

	w[2]^=w[15]^w[10]^w[4];
	w[2]=(w[2]<<1)|(w[2]>>31);
	b+=w[2];
	b+=0x5A827999;
	b+=(c<<5)|(c>>27);
	b+=((e^a)&d)^a;
	d=(d<<30)|(d>>2);

	w[3]^=w[0]^w[11]^w[5];
	w[3]=(w[3]<<1)|(w[3]>>31);
	a+=w[3];
	a+=0x5A827999;
	a+=(b<<5)|(b>>27);
	a+=((d^e)&c)^e;
	c=(c<<30)|(c>>2);

	w[4]^=w[1]^w[12]^w[6];
	w[4]=(w[4]<<1)|(w[4]>>31);
	e+=w[4];
	e+=0x6ED9EBA1;
	e+=(a<<5)|(a>>27);
	e+=b^c^d;
	b=(b<<30)|(b>>2);

	w[5]^=w[2]^w[13]^w[7];
	w[5]=(w[5]<<1)|(w[5]>>31);
	d+=w[5];
	d+=0x6ED9EBA1;
	d+=(e<<5)|(e>>27);
	d+=a^b^c;
	a=(a<<30)|(a>>2);

	w[6]^=w[3]^w[14]^w[8];
	w[6]=(w[6]<<1)|(w[6]>>31);
	c+=w[6];
	c+=0x6ED9EBA1;
	c+=(d<<5)|(d>>27);
	c+=e^a^b;
	e=(e<<30)|(e>>2);

	w[7]^=w[4]^w[15]^w[9];
	w[7]=(w[7]<<1)|(w[7]>>31);
	b+=w[7];
	b+=0x6ED9EBA1;
	b+=(c<<5)|(c>>27);
	b+=d^e^a;
	d=(d<<30)|(d>>2);

	w[8]^=w[5]^w[0]^w[10];
	w[8]=(w[8]<<1)|(w[8]>>31);
	a+=w[8];
	a+=0x6ED9EBA1;
	a+=(b<<5)|(b>>27);
	a+=c^d^e;
	c=(c<<30)|(c>>2);

	w[9]^=w[6]^w[1]^w[11];
	w[9]=(w[9]<<1)|(w[9]>>31);
	e+=w[9];
	e+=0x6ED9EBA1;
	e+=(a<<5)|(a>>27);
	e+=b^c^d;
	b=(b<<30)|(b>>2);

	w[10]^=w[7]^w[2]^w[12];
	w[10]=(w[10]<<1)|(w[10]>>31);
	d+=w[10];
	d+=0x6ED9EBA1;
	d+=(e<<5)|(e>>27);
	d+=a^b^c;
	a=(a<<30)|(a>>2);

	w[11]^=w[8]^w[3]^w[13];
	w[11]=(w[11]<<1)|(w[11]>>31);
	c+=w[11];
	c+=0x6ED9EBA1;
	c+=(d<<5)|(d>>27);
	c+=e^a^b;
	e=(e<<30)|(e>>2);

	w[12]^=w[9]^w[4]^w[14];
	w[12]=(w[12]<<1)|(w[12]>>31);
	b+=w[12];
	b+=0x6ED9EBA1;
	b+=(c<<5)|(c>>27);
	b+=d^e^a;
	d=(d<<30)|(d>>2);

	w[13]^=w[10]^w[5]^w[15];
	w[13]=(w[13]<<1)|(w[13]>>31);
	a+=w[13];
	a+=0x6ED9EBA1;
	a+=(b<<5)|(b>>27);
	a+=c^d^e;
	c=(c<<30)|(c>>2);

	w[14]^=w[11]^w[6]^w[0];
	w[14]=(w[14]<<1)|(w[14]>>31);
	e+=w[14];
	e+=0x6ED9EBA1;
	e+=(a<<5)|(a>>27);
	e+=b^c^d;
	b=(b<<30)|(b>>2);

	w[15]^=w[12]^w[7]^w[1];
	w[15]=(w[15]<<1)|(w[15]>>31);
	d+=w[15];
	d+=0x6ED9EBA1;
	d+=(e<<5)|(e>>27);
	d+=a^b^c;
	a=(a<<30)|(a>>2);

	w[0]^=w[13]^w[8]^w[2];
	w[0]=(w[0]<<1)|(w[0]>>31);
	c+=w[0];
	c+=0x6ED9EBA1;
	c+=(d<<5)|(d>>27);
	c+=e^a^b;
	e=(e<<30)|(e>>2);

	w[1]^=w[14]^w[9]^w[3];
	w[1]=(w[1]<<1)|(w[1]>>31);
	b+=w[1];
	b+=0x6ED9EBA1;
	b+=(c<<5)|(c>>27);
	b+=d^e^a;
	d=(d<<30)|(d>>2);

	w[2]^=w[15]^w[10]^w[4];
	w[2]=(w[2]<<1)|(w[2]>>31);
	a+=w[2];
	a+=0x6ED9EBA1;
	a+=(b<<5)|(b>>27);
	a+=c^d^e;
	c=(c<<30)|(c>>2);

	w[3]^=w[0]^w[11]^w[5];
	w[3]=(w[3]<<1)|(w[3]>>31);
	e+=w[3];
	e+=0x6ED9EBA1;
	e+=(a<<5)|(a>>27);
	e+=b^c^d;
	b=(b<<30)|(b>>2);

	w[4]^=w[1]^w[12]^w[6];
	w[4]=(w[4]<<1)|(w[4]>>31);
	d+=w[4];
	d+=0x6ED9EBA1;
	d+=(e<<5)|(e>>27);
	d+=a^b^c;
	a=(a<<30)|(a>>2);

	w[5]^=w[2]^w[13]^w[7];
	w[5]=(w[5]<<1)|(w[5]>>31);
	c+=w[5];
	c+=0x6ED9EBA1;
	c+=(d<<5)|(d>>27);
	c+=e^a^b;
	e=(e<<30)|(e>>2);

	w[6]^=w[3]^w[14]^w[8];
	w[6]=(w[6]<<1)|(w[6]>>31);
	b+=w[6];
	b+=0x6ED9EBA1;
	b+=(c<<5)|(c>>27);
	b+=d^e^a;
	d=(d<<30)|(d>>2);

	w[7]^=w[4]^w[15]^w[9];
	w[7]=(w[7]<<1)|(w[7]>>31);
	a+=w[7];
	a+=0x6ED9EBA1;
	a+=(b<<5)|(b>>27);
	a+=c^d^e;
	c=(c<<30)|(c>>2);

	w[8]^=w[5]^w[0]^w[10];
	w[8]=(w[8]<<1)|(w[8]>>31);
	e+=w[8];
	e+=0x8F1BBCDC;
	e+=(a<<5)|(a>>27);
	e+=(b&c)|((b|c)&d);
	b=(b<<30)|(b>>2);

	w[9]^=w[6]^w[1]^w[11];
	w[9]=(w[9]<<1)|(w[9]>>31);
	d+=w[9];
	d+=0x8F1BBCDC;
	d+=(e<<5)|(e>>27);
	d+=(a&b)|((a|b)&c);
	a=(a<<30)|(a>>2);

	w[10]^=w[7]^w[2]^w[12];
	w[10]=(w[10]<<1)|(w[10]>>31);
	c+=w[10];
	c+=0x8F1BBCDC;
	c+=(d<<5)|(d>>27);
	c+=(e&a)|((e|a)&b);
	e=(e<<30)|(e>>2);

	w[11]^=w[8]^w[3]^w[13];
	w[11]=(w[11]<<1)|(w[11]>>31);
	b+=w[11];
	b+=0x8F1BBCDC;
	b+=(c<<5)|(c>>27);
	b+=(d&e)|((d|e)&a);
	d=(d<<30)|(d>>2);

	w[12]^=w[9]^w[4]^w[14];
	w[12]=(w[12]<<1)|(w[12]>>31);
	a+=w[12];
	a+=0x8F1BBCDC;
	a+=(b<<5)|(b>>27);
	a+=(c&d)|((c|d)&e);
	c=(c<<30)|(c>>2);

	w[13]^=w[10]^w[5]^w[15];
	w[13]=(w[13]<<1)|(w[13]>>31);
	e+=w[13];
	e+=0x8F1BBCDC;
	e+=(a<<5)|(a>>27);
	e+=(b&c)|((b|c)&d);
	b=(b<<30)|(b>>2);

	w[14]^=w[11]^w[6]^w[0];
	w[14]=(w[14]<<1)|(w[14]>>31);
	d+=w[14];
	d+=0x8F1BBCDC;
	d+=(e<<5)|(e>>27);
	d+=(a&b)|((a|b)&c);
	a=(a<<30)|(a>>2);

	w[15]^=w[12]^w[7]^w[1];
	w[15]=(w[15]<<1)|(w[15]>>31);
	c+=w[15];
	c+=0x8F1BBCDC;
	c+=(d<<5)|(d>>27);
	c+=(e&a)|((e|a)&b);
	e=(e<<30)|(e>>2);

	w[0]^=w[13]^w[8]^w[2];
	w[0]=(w[0]<<1)|(w[0]>>31);
	b+=w[0];
	b+=0x8F1BBCDC;
	b+=(c<<5)|(c>>27);
	b+=(d&e)|((d|e)&a);
	d=(d<<30)|(d>>2);

	w[1]^=w[14]^w[9]^w[3];
	w[1]=(w[1]<<1)|(w[1]>>31);
	a+=w[1];
	a+=0x8F1BBCDC;
	a+=(b<<5)|(b>>27);
	a+=(c&d)|((c|d)&e);
	c=(c<<30)|(c>>2);

	w[2]^=w[15]^w[10]^w[4];
	w[2]=(w[2]<<1)|(w[2]>>31);
	e+=w[2];
	e+=0x8F1BBCDC;
	e+=(a<<5)|(a>>27);
	e+=(b&c)|((b|c)&d);
	b=(b<<30)|(b>>2);

	w[3]^=w[0]^w[11]^w[5];
	w[3]=(w[3]<<1)|(w[3]>>31);
	d+=w[3];
	d+=0x8F1BBCDC;
	d+=(e<<5)|(e>>27);
	d+=(a&b)|((a|b)&c);
	a=(a<<30)|(a>>2);

	w[4]^=w[1]^w[12]^w[6];
	w[4]=(w[4]<<1)|(w[4]>>31);
	c+=w[4];
	c+=0x8F1BBCDC;
	c+=(d<<5)|(d>>27);
	c+=(e&a)|((e|a)&b);
	e=(e<<30)|(e>>2);

	w[5]^=w[2]^w[13]^w[7];
	w[5]=(w[5]<<1)|(w[5]>>31);
	b+=w[5];
	b+=0x8F1BBCDC;
	b+=(c<<5)|(c>>27);
	b+=(d&e)|((d|e)&a);
	d=(d<<30)|(d>>2);

	w[6]^=w[3]^w[14]^w[8];
	w[6]=(w[6]<<1)|(w[6]>>31);
	a+=w[6];
	a+=0x8F1BBCDC;
	a+=(b<<5)|(b>>27);
	a+=(c&d)|((c|d)&e);
	c=(c<<30)|(c>>2);

	w[7]^=w[4]^w[15]^w[9];
	w[7]=(w[7]<<1)|(w[7]>>31);
	e+=w[7];
	e+=0x8F1BBCDC;
	e+=(a<<5)|(a>>27);
	e+=(b&c)|((b|c)&d);
	b=(b<<30)|(b>>2);

	w[8]^=w[5]^w[0]^w[10];
	w[8]=(w[8]<<1)|(w[8]>>31);
	d+=w[8];
	d+=0x8F1BBCDC;
	d+=(e<<5)|(e>>27);
	d+=(a&b)|((a|b)&c);
	a=(a<<30)|(a>>2);

	w[9]^=w[6]^w[1]^w[11];
	w[9]=(w[9]<<1)|(w[9]>>31);
	c+=w[9];
	c+=0x8F1BBCDC;
	c+=(d<<5)|(d>>27);
	c+=(e&a)|((e|a)&b);
	e=(e<<30)|(e>>2);

	w[10]^=w[7]^w[2]^w[12];
	w[10]=(w[10]<<1)|(w[10]>>31);
	b+=w[10];
	b+=0x8F1BBCDC;
	b+=(c<<5)|(c>>27);
	b+=(d&e)|((d|e)&a);
	d=(d<<30)|(d>>2);

	w[11]^=w[8]^w[3]^w[13];
	w[11]=(w[11]<<1)|(w[11]>>31);
	a+=w[11];
	a+=0x8F1BBCDC;
	a+=(b<<5)|(b>>27);
	a+=(c&d)|((c|d)&e);
	c=(c<<30)|(c>>2);

	w[12]^=w[9]^w[4]^w[14];
	w[12]=(w[12]<<1)|(w[12]>>31);
	e+=w[12];
	e+=0xCA62C1D6;
	e+=(a<<5)|(a>>27);
	e+=b^c^d;
	b=(b<<30)|(b>>2);

	w[13]^=w[10]^w[5]^w[15];
	w[13]=(w[13]<<1)|(w[13]>>31);
	d+=w[13];
	d+=0xCA62C1D6;
	d+=(e<<5)|(e>>27);
	d+=a^b^c;
	a=(a<<30)|(a>>2);

	w[14]^=w[11]^w[6]^w[0];
	w[14]=(w[14]<<1)|(w[14]>>31);
	c+=w[14];
	c+=0xCA62C1D6;
	c+=(d<<5)|(d>>27);
	c+=e^a^b;
	e=(e<<30)|(e>>2);

	w[15]^=w[12]^w[7]^w[1];
	w[15]=(w[15]<<1)|(w[15]>>31);
	b+=w[15];
	b+=0xCA62C1D6;
	b+=(c<<5)|(c>>27);
	b+=d^e^a;
	d=(d<<30)|(d>>2);

	w[0]^=w[13]^w[8]^w[2];
	w[0]=(w[0]<<1)|(w[0]>>31);
	a+=w[0];
	a+=0xCA62C1D6;
	a+=(b<<5)|(b>>27);
	a+=c^d^e;
	c=(c<<30)|(c>>2);

	w[1]^=w[14]^w[9]^w[3];
	w[1]=(w[1]<<1)|(w[1]>>31);
	e+=w[1];
	e+=0xCA62C1D6;
	e+=(a<<5)|(a>>27);
	e+=b^c^d;
	b=(b<<30)|(b>>2);

	w[2]^=w[15]^w[10]^w[4];
	w[2]=(w[2]<<1)|(w[2]>>31);
	d+=w[2];
	d+=0xCA62C1D6;
	d+=(e<<5)|(e>>27);
	d+=a^b^c;
	a=(a<<30)|(a>>2);

	w[3]^=w[0]^w[11]^w[5];
	w[3]=(w[3]<<1)|(w[3]>>31);
	c+=w[3];
	c+=0xCA62C1D6;
	c+=(d<<5)|(d>>27);
	c+=e^a^b;
	e=(e<<30)|(e>>2);

	w[4]^=w[1]^w[12]^w[6];
	w[4]=(w[4]<<1)|(w[4]>>31);
	b+=w[4];
	b+=0xCA62C1D6;
	b+=(c<<5)|(c>>27);
	b+=d^e^a;
	d=(d<<30)|(d>>2);

	w[5]^=w[2]^w[13]^w[7];
	w[5]=(w[5]<<1)|(w[5]>>31);
	a+=w[5];
	a+=0xCA62C1D6;
	a+=(b<<5)|(b>>27);
	a+=c^d^e;
	c=(c<<30)|(c>>2);

	w[6]^=w[3]^w[14]^w[8];
	w[6]=(w[6]<<1)|(w[6]>>31);
	e+=w[6];
	e+=0xCA62C1D6;
	e+=(a<<5)|(a>>27);
	e+=b^c^d;
	b=(b<<30)|(b>>2);

	w[7]^=w[4]^w[15]^w[9];
	w[7]=(w[7]<<1)|(w[7]>>31);
	d+=w[7];
	d+=0xCA62C1D6;
	d+=(e<<5)|(e>>27);
	d+=a^b^c;
	a=(a<<30)|(a>>2);

	w[8]^=w[5]^w[0]^w[10];
	w[8]=(w[8]<<1)|(w[8]>>31);
	c+=w[8];
	c+=0xCA62C1D6;
	c+=(d<<5)|(d>>27);
	c+=e^a^b;
	e=(e<<30)|(e>>2);

	w[9]^=w[6]^w[1]^w[11];
	w[9]=(w[9]<<1)|(w[9]>>31);
	b+=w[9];
	b+=0xCA62C1D6;
	b+=(c<<5)|(c>>27);
	b+=d^e^a;
	d=(d<<30)|(d>>2);

	w[10]^=w[7]^w[2]^w[12];
	w[10]=(w[10]<<1)|(w[10]>>31);
	a+=w[10];
	a+=0xCA62C1D6;
	a+=(b<<5)|(b>>27);
	a+=c^d^e;
	c=(c<<30)|(c>>2);

	w[11]^=w[8]^w[3]^w[13];
	w[11]=(w[11]<<1)|(w[11]>>31);
	e+=w[11];
	e+=0xCA62C1D6;
	e+=(a<<5)|(a>>27);
	e+=b^c^d;
	b=(b<<30)|(b>>2);

	w[12]^=w[9]^w[4]^w[14];
	w[12]=(w[12]<<1)|(w[12]>>31);
	d+=w[12];
	d+=0xCA62C1D6;
	d+=(e<<5)|(e>>27);
	d+=a^b^c;
	a=(a<<30)|(a>>2);

	w[13]^=w[10]^w[5]^w[15];
	w[13]=(w[13]<<1)|(w[13]>>31);
	c+=w[13];
	c+=0xCA62C1D6;
	c+=(d<<5)|(d>>27);
	c+=e^a^b;
	e=(e<<30)|(e>>2);

	w[14]^=w[11]^w[6]^w[0];
	w[14]=(w[14]<<1)|(w[14]>>31);
	b+=w[14];
	b+=0xCA62C1D6;
	b+=(c<<5)|(c>>27);
	b+=d^e^a;
	d=(d<<30)|(d>>2);

	w[15]^=w[12]^w[7]^w[1];
	w[15]=(w[15]<<1)|(w[15]>>31);
	a+=w[15];
	a+=0xCA62C1D6;
	a+=(b<<5)|(b>>27);
	a+=c^d^e;
	c=(c<<30)|(c>>2);

	sha1[0]+=a;
	sha1[1]+=b;
	sha1[2]+=c;
	sha1[3]+=d;
	sha1[4]+=e;
}

void neosc_sha1init(register NEOSC_SHA1DATA *ptr)
{
	ptr->total=ptr->size=0;
	ptr->sha1[0]=0x67452301;
	ptr->sha1[1]=0xEFCDAB89;
	ptr->sha1[2]=0x98BADCFE;
	ptr->sha1[3]=0x10325476;
	ptr->sha1[4]=0xC3D2E1F0;
}

void neosc_sha1next(register unsigned char *data,register unsigned int length,
	register NEOSC_SHA1DATA *ptr)
{
	register unsigned int i;

	ptr->total+=length;

	for(i=ptr->size;(i&63)&&length;length--)ptr->bfr.b[i++]=*data++;

	if(i==64)
	{
		i=0;
		sha1block(ptr->sha1,ptr->bfr.b);
	}

	for(;length>63;length-=64,data+=64)sha1block(ptr->sha1,data);
	for(;length;length--)ptr->bfr.b[i++]=*data++;
	ptr->size=(unsigned char)(i);
}

void neosc_sha1end(register unsigned char *result,register NEOSC_SHA1DATA *ptr)
{
	register unsigned int i=ptr->size;

	ptr->bfr.b[i++]=0x80;
	if(i>56)
	{
		for(;i<64;i++)ptr->bfr.b[i]=0;
		i=0;
		sha1block(ptr->sha1,ptr->bfr.b);
	}
	for(;i<56;i++)ptr->bfr.b[i]=0;

	ptr->bfr.b[56]=0;
	ptr->bfr.b[57]=0;
	ptr->bfr.b[58]=0;
	ptr->bfr.b[59]=(unsigned char)((ptr->total)>>29);
	ptr->bfr.b[60]=(unsigned char)((ptr->total)>>21);
	ptr->bfr.b[61]=(unsigned char)((ptr->total)>>13);
	ptr->bfr.b[62]=(unsigned char)((ptr->total)>>5);
	ptr->bfr.b[63]=(unsigned char)((ptr->total)<<3);

	sha1block(ptr->sha1,ptr->bfr.b);

	result[ 0]=(unsigned char)((ptr->sha1[0])>>24);
	result[ 1]=(unsigned char)((ptr->sha1[0])>>16);
	result[ 2]=(unsigned char)((ptr->sha1[0])>>8);
	result[ 3]=(unsigned char) (ptr->sha1[0]);
	result[ 4]=(unsigned char)((ptr->sha1[1])>>24);
	result[ 5]=(unsigned char)((ptr->sha1[1])>>16);
	result[ 6]=(unsigned char)((ptr->sha1[1])>>8);
	result[ 7]=(unsigned char) (ptr->sha1[1]);
	result[ 8]=(unsigned char)((ptr->sha1[2])>>24);
	result[ 9]=(unsigned char)((ptr->sha1[2])>>16);
	result[10]=(unsigned char)((ptr->sha1[2])>>8);
	result[11]=(unsigned char) (ptr->sha1[2]);
	result[12]=(unsigned char)((ptr->sha1[3])>>24);
	result[13]=(unsigned char)((ptr->sha1[3])>>16);
	result[14]=(unsigned char)((ptr->sha1[3])>>8);
	result[15]=(unsigned char) (ptr->sha1[3]);
	result[16]=(unsigned char)((ptr->sha1[4])>>24);
	result[17]=(unsigned char)((ptr->sha1[4])>>16);
	result[18]=(unsigned char)((ptr->sha1[4])>>8);
	result[19]=(unsigned char) (ptr->sha1[4]);
}

void neosc_sha1(register unsigned char *data,register unsigned int length,
	unsigned char *result)
{
	register unsigned int i;
	unsigned int total;
	unsigned int sha1[5];
	unsigned char bfr[64];

	total=length;
	sha1[0]=0x67452301;
	sha1[1]=0xEFCDAB89;
	sha1[2]=0x98BADCFE;
	sha1[3]=0x10325476;
	sha1[4]=0xC3D2E1F0;

	for(;length>63;length-=64,data+=64)sha1block(sha1,data);
	for(i=0;length;length--)bfr[i++]=*data++;
	bfr[i++]=0x80;
	if(i>56)
	{
		for(;i<64;i++)bfr[i]=0;
		i=0;
		sha1block(sha1,bfr);
	}
	for(;i<56;i++)bfr[i]=0;
	bfr[56]=0;
	bfr[57]=0;
	bfr[58]=0;
	bfr[59]=(unsigned char)((total)>>29);
	bfr[60]=(unsigned char)(total>>21);
	bfr[61]=(unsigned char)(total>>13);
	bfr[62]=(unsigned char)(total>>5);
	bfr[63]=(unsigned char)(total<<3);

	sha1block(sha1,bfr);

	result[ 0]=(unsigned char)((sha1[0])>>24);
	result[ 1]=(unsigned char)((sha1[0])>>16);
	result[ 2]=(unsigned char)((sha1[0])>>8);
	result[ 3]=(unsigned char) (sha1[0]);
	result[ 4]=(unsigned char)((sha1[1])>>24);
	result[ 5]=(unsigned char)((sha1[1])>>16);
	result[ 6]=(unsigned char)((sha1[1])>>8);
	result[ 7]=(unsigned char) (sha1[1]);
	result[ 8]=(unsigned char)((sha1[2])>>24);
	result[ 9]=(unsigned char)((sha1[2])>>16);
	result[10]=(unsigned char)((sha1[2])>>8);
	result[11]=(unsigned char) (sha1[2]);
	result[12]=(unsigned char)((sha1[3])>>24);
	result[13]=(unsigned char)((sha1[3])>>16);
	result[14]=(unsigned char)((sha1[3])>>8);
	result[15]=(unsigned char) (sha1[3]);
	result[16]=(unsigned char)((sha1[4])>>24);
	result[17]=(unsigned char)((sha1[4])>>16);
	result[18]=(unsigned char)((sha1[4])>>8);
	result[19]=(unsigned char) (sha1[4]);
}

void neosc_sha1hmkey(unsigned char *key,unsigned int keylength,
	NEOSC_SHA1HMDATA *ptr)
{
	register unsigned int i;
	NEOSC_SHA1(hash);
	union
	{
		unsigned char pad[64];
		NEOSC_SHA1DATA sha1data;
	}u;

	if(keylength>64)
	{
		neosc_sha1init(&u.sha1data);
		neosc_sha1next(key,keylength,&u.sha1data);
		neosc_sha1end(hash,&u.sha1data);
		key=hash;
		keylength=NEOSC_SHA1_SIZE;
		u.sha1data.sha1[0]=u.sha1data.sha1[1]=
			u.sha1data.sha1[2]=u.sha1data.sha1[3]=
			u.sha1data.sha1[4]=0;
	}

	ptr->isha1[0]=ptr->osha1[0]=0x67452301;
	ptr->isha1[1]=ptr->osha1[1]=0xEFCDAB89;
	ptr->isha1[2]=ptr->osha1[2]=0x98BADCFE;
	ptr->isha1[3]=ptr->osha1[3]=0x10325476;
	ptr->isha1[4]=ptr->osha1[4]=0xC3D2E1F0;

	for(i=0;i<keylength;i++)u.pad[i]=key[i]^0x36;
	for(;i<64;i++)u.pad[i]=0x36;
	sha1block(ptr->isha1,u.pad);

	for(i=0;i<keylength;i++)u.pad[i]=key[i]^0x5c;
	for(;i<64;i++)u.pad[i]=0x5c;
	sha1block(ptr->osha1,u.pad);

	for(i=0;i<NEOSC_SHA1_SIZE;i++)hash[i]=0;
	for(i=0;i<64;i++)u.pad[i]=0;
}

void neosc_sha1hminit(NEOSC_SHA1DATA *ptr,NEOSC_SHA1HMDATA *key)
{
	ptr->total=64;
	ptr->size=0;
	ptr->sha1[0]=key->isha1[0];
	ptr->sha1[1]=key->isha1[1];
	ptr->sha1[2]=key->isha1[2];
	ptr->sha1[3]=key->isha1[3];
	ptr->sha1[4]=key->isha1[4];
}

void neosc_sha1hmend(unsigned char *result,NEOSC_SHA1DATA *ptr,
	NEOSC_SHA1HMDATA *key)
{
	neosc_sha1end(result,ptr);

	ptr->total=64;
	ptr->size=0;
	ptr->sha1[0]=key->osha1[0];
	ptr->sha1[1]=key->osha1[1];
	ptr->sha1[2]=key->osha1[2];
	ptr->sha1[3]=key->osha1[3];
	ptr->sha1[4]=key->osha1[4];

	neosc_sha1next(result,NEOSC_SHA1_SIZE,ptr);
	neosc_sha1end(result,ptr);
}

void neosc_sha1hmac(unsigned char *data,unsigned int length,
	unsigned char *result,NEOSC_SHA1HMDATA *key)
{
	NEOSC_SHA1DATA sha1data;

	sha1data.total=64;
	sha1data.size=0;
	sha1data.sha1[0]=key->isha1[0];
	sha1data.sha1[1]=key->isha1[1];
	sha1data.sha1[2]=key->isha1[2];
	sha1data.sha1[3]=key->isha1[3];
	sha1data.sha1[4]=key->isha1[4];

	neosc_sha1next(data,length,&sha1data);
	neosc_sha1end(result,&sha1data);

	sha1data.total=64;
	sha1data.size=0;
	sha1data.sha1[0]=key->osha1[0];
	sha1data.sha1[1]=key->osha1[1];
	sha1data.sha1[2]=key->osha1[2];
	sha1data.sha1[3]=key->osha1[3];
	sha1data.sha1[4]=key->osha1[4];

	neosc_sha1next(result,NEOSC_SHA1_SIZE,&sha1data);
	neosc_sha1end(result,&sha1data);
}
