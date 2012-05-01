/*
 * This piece of code belongs to libwww. The copyright of W3C is fully 
 * respected. Necessary changes have been made visible in the code.
 *
 * libwww Copyright Notice 
 *
 * libwww: W3C's implementation of HTTP can be found at: http://www.w3.org/Library/ 
 * Copyright © 1994-2000 World Wide Web Consortium, (Massachusetts Institute of 
 * Technology, Institut National de Recherche en Informatique et en Automatique, 
 * Keio University). All Rights Reserved. 
 * This program is distributed under the W3C's Software Intellectual Property License. 
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY 
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A 
 * PARTICULAR PURPOSE. See W3C License http://www.w3.org/Consortium/Legal/ for more 
 * details. 
 * Copyright © 1995 CERN. "This product includes computer software created and made 
 * available by CERN. This acknowledgment shall be mentioned in full in any product 
 * which includes the CERN computer software included herein or parts thereof."
 *
*/

/* Library include files */
#include "wwwsys.h"
#include "HTEscape.h"					 /* Implemented here */


#define HEX_ESCAPE '%'
#define ACCEPTABLE(a)	( a>=32 && a<128 && ((isAcceptable[a-32]) & mask))

/*
 * **  Not BOTH static AND const at the same time in gcc :-(, Henrik 18/03-94 
 * **  code gen error in gcc when making random access to static const table(!!)
*/

/*
 * **	Bit 0		xalpha		-- see HTFile.h
 * **	Bit 1		xpalpha		-- as xalpha but with plus.
 * **	Bit 2 ...	path		-- as xpalpha but with /
*/
unsigned char isAcceptable[96] =
{/* 0x0 0x1 0x2 0x3 0x4 0x5 0x6 0x7 0x8 0x9 0xA 0xB 0xC 0xD 0xE 0xF */
    0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0xF,0xE,0x0,0xF,0xF,0xC, /* 2x  !"#$%&'()*+,-./   */
    0xF,0xF,0xF,0xF,0xF,0xF,0xF,0xF,0xF,0xF,0x8,0x0,0x0,0x0,0x0,0x0, /* 3x 0123456789:;<=>?   */
    0xF,0xF,0xF,0xF,0xF,0xF,0xF,0xF,0xF,0xF,0xF,0xF,0xF,0xF,0xF,0xF, /* 4x @ABCDEFGHIJKLMNO   */
    0xF,0xF,0xF,0xF,0xF,0xF,0xF,0xF,0xF,0xF,0xF,0x0,0x0,0x0,0x0,0xF, /* 5X PQRSTUVWXYZ[\]^_   */
    0x0,0xF,0xF,0xF,0xF,0xF,0xF,0xF,0xF,0xF,0xF,0xF,0xF,0xF,0xF,0xF, /* 6x `abcdefghijklmno   */
    0xF,0xF,0xF,0xF,0xF,0xF,0xF,0xF,0xF,0xF,0xF,0x0,0x0,0x0,0x0,0x0  /* 7X pqrstuvwxyz{\}~DEL */
};
char *hex = "0123456789ABCDEF";

/* ------------------------------------------------------------------------- */
/*
 * 16.3.2007 Chris Kronberg: Removed function HTEscape() as we do not need
 *                           this one for squidGuard.
*/


char HTAsciiHexToChar (char c)
{
    return  c >= '0' && c <= '9' ?  c - '0' 
    	    : c >= 'A' && c <= 'F'? c - 'A' + 10
    	    : c - 'a' + 10;	/* accept small letters just in case */
}

/*		Decode %xx escaped characters			HTUnEscape()
 *		**		-----------------------------
 *		**
 *		**	This function takes a pointer to a string in which some
 *		**	characters may have been encoded in %xy form, where xy is
 *		**	the acsii hex code for character 16x+y.
 *		**	The string is converted in place, as it will never grow.
 *		*/
char * HTUnEscape (char * str)
{
    char * p = str;
    char * q = str;

/* 16.3.2007 Chris Kronberg: Removed Null entry test. In our case not relevant. */

    if (!(p && *p))
        return str;

    while(*p != '\0') {
        if (*p == HEX_ESCAPE ) {
            if ( p[1] == '2' && p[2]  == '0' ) { 
               /* 16.3.2007 Christine Kronberg */
               /* We do not want to decode the whitespace */
               *q++ = *p++;
            }
            else 
            {
            p++;
	    if (*p) {
               *q = HTAsciiHexToChar(*p++) * 16;
            }
#if 1
	    /* Suggestion from Markku Savela */
	    if (*p) {
               *q = FROMASCII(*q + HTAsciiHexToChar(*p)), ++p;
            }
	    q++;
#else 
	    if (*p) {
               *q = FROMASCII(*q + HTAsciiHexToChar(*p));
            }
	    p++, q++;
#endif
           }
	} else {
	    *q++ = *p++; 
	}
    }
    
    *q++ = 0;
    return str;
    
} /* HTUnEscape */
