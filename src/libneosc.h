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

#ifndef _LIBNEOSC_INCLUDED
#define _LIBNEOSC_INCLUDED

#include <time.h>

#ifdef __cplusplus
extern "C"
{
#endif

#define NEOSC_ANY_YUBIKEY	0
#define NEOSC_USB_YUBIKEY	-1
#define NEOSC_NFC_YUBIKEY	-2

#define NEOSC_APDU_BUFFER	264

#define NEOSC_OATH_NAMELEN	64
#define NEOSC_OATH_STEP		30
#define NEOSC_OATH_HOTP		0
#define NEOSC_OATH_TOTP		1
#define NEOSC_OATH_SHA1		0
#define NEOSC_OATH_SHA256	1

#define NEOSC_SHA256_SIZE	32
#define NEOSC_SHA1_SIZE		20
#define NEOSC_SHA1(a)		unsigned char a[NEOSC_SHA1_SIZE]

#define NEOSC_TKT_TAB0		0x01
#define NEOSC_TKT_TAB1		0x02
#define NEOSC_TKT_TAB2		0x04
#define NEOSC_TKT_DELAY1	0x08
#define NEOSC_TKT_DELAY2	0x10
#define NEOSC_TKT_CR		0x20
#define NEOSC_TKT_PROTECT2	0x80

#define NEOSC_CFG_HMAC_063	0x04
#define NEOSC_CFG_HMAC_BTN	0x08

#define NEOSC_CFG_OTP_BTN	0x08

#define NEOSC_CFG_HOTP_SENDREF	0x01
#define NEOSC_CFG_HOTP_8	0x02
#define NEOSC_CFG_HOTP_PACE_10	0x04
#define NEOSC_CFG_HOTP_PACE_20	0x08
#define NEOSC_CFG_HOTP_MODHEX1	0x10
#define NEOSC_CFG_HOTP_MODHEX2	0x40

#define NEOSC_CFG_YUBI_SENDREF	0x01
#define NEOSC_CFG_YUBI_PACE_10	0x04
#define NEOSC_CFG_YUBI_PACE_20	0x08

#define NEOSC_CFG_PASS_SENDREF	0x01
#define NEOSC_CFG_PASS_SHORT	0x02
#define NEOSC_CFG_PASS_PACE_10	0x04
#define NEOSC_CFG_PASS_PACE_20	0x08
#define NEOSC_CFG_PASS_STRONG_1	0x10
#define NEOSC_CFG_PASS_STRONG_2	0x40
#define NEOSC_CFG_PASS_MANUAL	0x80

#define NEOSC_EXT_SERIAL_BTN	0x01
#define NEOSC_EXT_SERIAL_USB	0x02
#define NEOSC_EXT_SERIAL_API	0x04
#define NEOSC_EXT_NUMPAD	0x08
#define NEOSC_EXT_FASTTRIG	0x10
#define NEOSC_EXT_UPDATE	0x20
#define NEOSC_EXT_DORMANT	0x40
#define NEOSC_EXT_LEDINV	0x80

#define NEOSC_NDEF_TEXT		0
#define NEOSC_NDEF_URL		1

#define NEOSC_MODE_OTP		0x00
#define NEOSC_MODE_CCID		0x01
#define NEOSC_MODE_OTP_CCID	0x02
#define NEOSC_MODE_U2F		0x03 /* danger! requires NFC to change from */
#define NEOSC_MODE_OTP_U2F	0x04
#define NEOSC_MODE_U2F_CCID	0x05
#define NEOSC_MODE_OTP_U2F_CCID	0x06

typedef struct
{
	int type;
	char language[NEOSC_APDU_BUFFER];
	char payload[NEOSC_APDU_BUFFER];
} NEOSC_NDEF;

typedef struct
{
	int major;
	int minor;
	int build;
	int pgmseq;
	int touchlevel;
	int config1;
	int config2;
	int touch1;
	int touch2;
	int ledinv;
} NEOSC_STATUS;

typedef struct
{
	int major;
	int minor;
	int build;
	int pgmseq;
	int touchlevel;
	int mode;
	int crtimeout;
	int autoejecttime;
	int config1;
	int config2;
	int touch1;
	int touch2;
	int ledinv;
} NEOSC_NEO_INFO;

typedef struct
{
	int version;
	int mle;
	int mlc;
	int fileid;
	int ndef_max;
	int rcond;
	int wcond;
} NEOSC_NDEF_CC;

typedef struct
{
	int major;
	int minor;
	int build;
	int protected;
	unsigned char identity[8];
	unsigned char challenge[8];
} NEOSC_OATH_INFO;

typedef struct
{
	int digits;
	int value;
	char name[NEOSC_OATH_NAMELEN+1];
} NEOSC_OATH_RESPONSE;

typedef struct
{
	int otpmode;
	int shamode;
	char name[NEOSC_OATH_NAMELEN+1];
} NEOSC_OATH_LIST;

typedef struct
{
	unsigned int sha1[5];
	unsigned int total;
	union
	{
		unsigned int l[16];
		unsigned char b[64];
	} bfr;
	unsigned char size;
} NEOSC_SHA1DATA;

typedef struct
{
	unsigned int isha1[5];
	unsigned int osha1[5];
} NEOSC_SHA1HMDATA;

extern char *neosc_util_id2uri(int id);
extern int neosc_util_uri2id(char *uri);
extern int neosc_util_sha1_to_otp(unsigned char *in,int ilen,int digits,
	int *out);
extern int neosc_util_time_to_array(time_t time,unsigned char *out,int olen);
extern int neosc_util_random(unsigned char *out,int olen);
extern int neosc_util_modhex_encode(unsigned char *in,int ilen,char *out,
	int *olen);
extern int neosc_util_modhex_decode(char *in,int ilen,unsigned char *out,
	int *olen);
extern int neosc_util_hex_encode(unsigned char *in,int ilen,char *out,
	int *olen);
extern int neosc_util_hex_decode(char *in,int ilen,unsigned char *out,
	int *olen);
extern int neosc_util_base64_encode(unsigned char *in,int ilen,char *out,
	int *olen);
extern int neosc_util_base64_decode(char *in,int ilen,unsigned char *out,
	int *olen);
extern int neosc_util_base32_encode(unsigned char *in,int ilen,char *out,
	int *olen);
extern int neosc_util_base32_decode(char *in,int ilen,unsigned char *out,
	int *olen);
extern int neosc_util_qrurl(char *name,int otpmode,int shamode,int digits,
	unsigned int counter,unsigned char *secret,int slen,char *out,int olen);

extern int neosc_neo_select(void *ctx,NEOSC_NEO_INFO *info);
extern int neosc_neo_read_serial(void *ctx,int *serial);
extern int neosc_neo_read_hmac(void *ctx,int slot,unsigned char *in,int ilen,
	unsigned char *out,int olen);
extern int neosc_neo_read_otp(void *ctx,int slot,unsigned char *in,int ilen,
	unsigned char *out,int olen);
extern int neosc_neo_read_status(void *ctx,NEOSC_STATUS *state);
extern int neosc_neo_read_ndef(void *ctx,NEOSC_NDEF *data);
extern int neosc_neo_read_yubiotp(void *ctx,int slot,char *out,int olen);
extern int neosc_neo_write_ndef(void *ctx,int slot,char *url,char *txt,
	char *lang,unsigned char *code,int codelen);
extern int neosc_neo_write_scanmap(void *ctx,unsigned char *map,int maplen);
extern int neosc_neo_setmode(void *ctx,int mode,int crtimeout,
	int autoejecttime);
extern int neosc_neo_reset(void *ctx,int slot);
extern int neosc_neo_config(void *ctx,unsigned char *apdu4,int tktflags,
	int cfgflags,int extflags,unsigned char *fixeddata,int fixedlen,
	unsigned char *uidpart,int uidlen,unsigned char *aesdata,int aeslen,
	unsigned char *newcode,int newlen,unsigned char *code,int codelen);
extern int neosc_neo_swap(void *ctx,unsigned char *newcode,int newlen,
	unsigned char *code,int codelen);
extern int neosc_neo_update(void *ctx,int slot,int tktflags,int cfgflags,
	int extflags,unsigned char *newcode,int newlen,unsigned char *code,
	int codelen);
extern int neosc_neo_hmac(void *ctx,int slot,unsigned char *aesdata,int aeslen,
	int tktflags,int cfgflags,int extflags,unsigned char *newcode,
	int newlen,unsigned char *code,int codelen);
extern int neosc_neo_otp(void *ctx,int slot,unsigned char *privid,int privlen,
	unsigned char *aesdata,int aeslen,int tktflags,int cfgflags,
	int extflags,unsigned char *newcode,int newlen,unsigned char *code,
	int codelen);
extern int neosc_neo_hotp(void *ctx,int slot,int omp,int tt,int mui,int imf,
	unsigned char *aesdata,int aeslen,int tktflags,int cfgflags,
	int extflags,unsigned char *newcode,int newlen,unsigned char *code,
	int codelen);
extern int neosc_neo_yubiotp(void *ctx,int slot,unsigned char *pubid,int publen,
	unsigned char *privid,int privlen,unsigned char *aesdata,int aeslen,
	int tktflags,int cfgflags,int extflags,unsigned char *newcode,
	int newlen,unsigned char *code,int codelen);
extern int neosc_neo_passwd(void *ctx,int slot,unsigned char *pubid,int publen,
	unsigned char *privid,int privlen,unsigned char *aesdata,int aeslen,
	int tktflags,int cfgflags,int extflags,unsigned char *newcode,
	int newlen,unsigned char *code,int codelen);

extern int neosc_ndef_select(void *ctx);
extern int neosc_ndef_read_cc(void *ctx,NEOSC_NDEF_CC *data);
extern int neosc_ndef_read_ndef(void *ctx,NEOSC_NDEF *data);

extern int neosc_oath_select(void *ctx,NEOSC_OATH_INFO *info);
extern int neosc_oath_reset(void *ctx);
extern int neosc_oath_unlock(void *ctx,char *password,NEOSC_OATH_INFO *info);
extern int neosc_oath_chgpass(void *ctx,char *password,NEOSC_OATH_INFO *info);
extern int neosc_oath_calc_single(void *ctx,char *name,time_t time,
	NEOSC_OATH_RESPONSE *result);
extern int neosc_oath_calc_all(void *ctx,time_t time,
	NEOSC_OATH_RESPONSE **result,int *total);
extern int neosc_oath_list_all(void *ctx,NEOSC_OATH_LIST **result,int *total);
extern int neosc_oath_delete(void *ctx,char *name);
extern int neosc_oath_add(void *ctx,char *name,int otpmode,int shamode,
	int digits,unsigned int counter,unsigned char *secret,int slen);

extern int neosc_pgp_select(void *ctx);

extern int neosc_piv_select(void *ctx);

extern void neosc_pbkdf2(char *pass,unsigned char *salt,int slen,int iterations,
	unsigned char *out,int olen);

extern void neosc_sha1init(NEOSC_SHA1DATA *ptr);
extern void neosc_sha1next(unsigned char *data,unsigned int length,
	NEOSC_SHA1DATA *ptr);
extern void neosc_sha1end(unsigned char *result,NEOSC_SHA1DATA *ptr);
extern void neosc_sha1(unsigned char *data,unsigned int length,
	unsigned char *result);
extern void neosc_sha1hmkey(unsigned char *key,unsigned int keylength,
	NEOSC_SHA1HMDATA *ptr);
extern void neosc_sha1hminit(NEOSC_SHA1DATA *ptr,NEOSC_SHA1HMDATA *key);
#define neosc_sha1hmnext(a,b,c) neosc_sha1next(a,b,c)
extern void neosc_sha1hmend(unsigned char *result,NEOSC_SHA1DATA *ptr,
	NEOSC_SHA1HMDATA *key);
extern void neosc_sha1hmac(unsigned char *data,unsigned int length,
	unsigned char *result,NEOSC_SHA1HMDATA *key);

extern int neosc_pcsc_apdu(void *ctx,unsigned char *in,int ilen,
	unsigned char *out,int *olen,int *status);
extern int neosc_pcsc_lock(void *ctx);
extern int neosc_pcsc_unlock(void *ctx);
extern int neosc_pcsc_open(void **ctx,int serial);
extern void neosc_pcsc_close(void *ctx);

extern void neosc_usb_close(void *handle);
extern int neosc_usb_open(void **handle,int serial,int *mode);
extern int neosc_usb_read_status(void *handle,NEOSC_STATUS *status);
extern int neosc_usb_read_serial(void *handle,int *serial);
extern int neosc_usb_read_hmac(void *handle,int slot,unsigned char *in,int ilen,
	unsigned char *out,int olen);
extern int neosc_usb_read_otp(void *handle,int slot,unsigned char *in,int ilen,
	unsigned char *out,int olen);
extern int neosc_usb_write_ndef(void *handle,int slot,char *url,char *txt,
	char *lang,unsigned char *code,int codelen);
extern int neosc_usb_write_scanmap(void *handle,unsigned char *map,int maplen);
extern int neosc_usb_setmode(void *handle,int mode,int crtimeout,
	int autoejecttime);
extern int neosc_usb_reset(void *handle,int slot);
extern int neosc_usb_config(void *handle,int command,int tktflags,int cfgflags,
	int extflags,unsigned char *fixeddata,int fixedlen,
	unsigned char *uidpart,int uidlen,unsigned char *aesdata,int aeslen,
	unsigned char *newcode,int newlen,unsigned char *code,int codelen);
extern int neosc_usb_swap(void *handle,unsigned char *newcode,int newlen,
	unsigned char *code,int codelen);
extern int neosc_usb_update(void *handle,int slot,int tktflags,int cfgflags,
        int extflags,unsigned char *newcode,int newlen,unsigned char *code,
	int codelen);
extern int neosc_usb_hmac(void *handle,int slot,unsigned char *aesdata,
	int aeslen,int tktflags,int cfgflags,int extflags,
	unsigned char *newcode,int newlen,unsigned char *code,int codelen);
extern int neosc_usb_otp(void *handle,int slot,unsigned char *privid,
	int privlen,unsigned char *aesdata,int aeslen,int tktflags,int cfgflags,
        int extflags,unsigned char *newcode,int newlen,unsigned char *code,
        int codelen);
extern int neosc_usb_hotp(void *handle,int slot,int omp,int tt,int mui,int imf,
        unsigned char *aesdata,int aeslen,int tktflags,int cfgflags,
        int extflags,unsigned char *newcode,int newlen,unsigned char *code,
        int codelen);
extern int neosc_usb_yubiotp(void *handle,int slot,unsigned char *pubid,
	int publen,unsigned char *privid,int privlen,unsigned char *aesdata,
	int aeslen,int tktflags,int cfgflags,int extflags,
	unsigned char *newcode,int newlen,unsigned char *code,int codelen);
extern int neosc_usb_passwd(void *handle,int slot,unsigned char *pubid,
	int publen,unsigned char *privid,int privlen,unsigned char *aesdata,
	int aeslen,int tktflags,int cfgflags,int extflags,
	unsigned char *newcode,int newlen,unsigned char *code,int codelen);

#ifdef __cplusplus
}
#endif

#endif
