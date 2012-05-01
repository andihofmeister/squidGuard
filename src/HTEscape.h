/*
* This piece of code belongs to libwww. The copyright of W3C is fully
* respected:
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

#ifndef HTESCAPE_H
#define HTESCAPE_H

typedef enum _HTURIEncoding {
    URL_XALPHAS		= 0x1,     /* Escape all unsafe characters */
    URL_XPALPHAS	= 0x2,     /* As URL_XALPHAS but allows '+' */
    URL_PATH		= 0x4,     /* As URL_XPALPHAS but allows '/' */
    URL_DOSFILE         = 0x8      /* As URL_URLPATH but allows ':' */
} HTURIEncoding;

extern char * HTEscape (const char * str, HTURIEncoding mask);

extern char HTAsciiHexToChar (char c);

extern char * HTUnEscape (char * str);
#endif	/* HTESCAPE_H */
