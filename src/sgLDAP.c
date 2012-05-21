#include <stdlib.h>
#include <stdio.h>

#include "config.h"
#include "sgMatch.h"
#include "sgSetting.h"
#include "sgMemory.h"
#include "sgLog.h"
#include "sgLDAP.h"

#ifndef HAVE_LIBLDAP

struct SourceMatch *newLDAPUserMatch(const char *url)
{
	sgLogFatal("this SquidGuard has not been compiled with LDAP support");
	return NULL;
}

struct SourceMatch *newLDAPIPMatch(const char *url)
{
	sgLogFatal("this SquidGuard has not been compiled with LDAP support");
	return NULL;
}

#else

#define LDAP_DEPRECATED 1
#include "lber.h"
#include "ldap.h"

static int get_ldap_errno(LDAP *ld)
{
	int err = 0;

	if (ld)
		if (ldap_get_option(ld, LDAP_OPT_ERROR_NUMBER, &err) != LDAP_OPT_SUCCESS)
			err = 0;
	return err;
}

/*
 * expand_url - expand the %s codes in the given LDAP url
 *
 * Returns:  1 on success, 0 on error
 *
 *   char *expand;             destination buffer for expanded URL
 *   size_t expand_size;       size of dest buffer (sizeof() works here)
 *   char *url;                        original URL (MAXWORDLEN)
 *   char *s_item;             word to replace each occurance of %s with
 */
static int expandUrl(char *expand, size_t expand_size, const char *url,
		     const char *s_item)
{
	int item_length;
	char *end = expand + expand_size;

	sgLogDebug("expanding URL '%s' with item '%s'", url, s_item);

	item_length = strlen(s_item);

	while (*url && expand < end) {
		if (url[0] == '%' && url[1] == 's') {
			/* check buffer overrun */
			if ((expand + item_length) >= end)
				return 0;
			strcpy(expand, s_item);
			expand += item_length;

			url += 2;
		} else {
			*expand++ = *url++;
		}
	}

	if (expand < end) {
		*expand = '\0';        /* null terminate string */
		return 1;
	} else {
		return 0;
	}
}


/* does a raw LDAP search and returns 1 if found, 0 if not */
static int doLdapSearch(const char *url, const char *username)
{
	LDAPURLDesc *lud;
	LDAP *ld;
	int lderr = 0;
	LDAPMessage *ldapresult = NULL;
	LDAPMessage *ldapentry = NULL;
	const char *binddn = NULL;
	const char *bindpass = NULL;
	int ext_i;
	char **ldapvals;
	char buffer[MAX_BUF];
	int found = 0;
	int protoversion = -1;                 /* default to library defaults*/
	const char *protosetting = getSetting("ldapprotover");

	/* Which protocol version should we use? */
	if (protosetting != NULL) {
		if (atoi(protosetting) == 3)
			protoversion = LDAP_VERSION3;
		else if (atoi(protosetting) == 2)
			protoversion = LDAP_VERSION2;
	}

	/* insert the username into the url, if needed... allow multiple %s */
	if (!expandUrl(buffer, sizeof(buffer), url, username)) {
		sgLogError("unable to expand LDAP URL: size: %u, username: "
			   "%s url: %s", sizeof(buffer), username, url);
		return found;
	}

	/* Parse RFC2255 LDAP URL */
	if (ldap_url_parse(buffer, &lud)) {
		sgLogError("can't parse expanded LDAP url '%s'", buffer);
		return found;
	}

	/* get a handle to an LDAP connection */
	if (ldap_is_ldapi_url(url)) {
		char *c = NULL;
		strncpy(buffer, url, sizeof(buffer));
		if ((c = strchr(buffer + strlen("ldapi://"), '/')) != NULL)
			*c = 0;
	} else {
		snprintf(buffer, sizeof(buffer), "%s://%s:%d", lud->lud_scheme, lud->lud_host, lud->lud_port);
	}

	if ((lderr = ldap_initialize(&ld, buffer)) != LDAP_SUCCESS) {
		sgLogError("ldap_initialize(%s) failed: %s",
			   buffer, ldap_err2string(lderr));
		ldap_free_urldesc(lud);
		return found;
	}

	/* force an LDAP protocol version if set */
	if (protoversion != -1) {
		if (ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION,
				    &protoversion) != LDAP_OPT_SUCCESS) {
			/* this will enter emergency mode */
			sgLogFatal("ldap_set_option failed: %s",
				   ldap_err2string(get_ldap_errno(ld)));
		}
	}

	/*
	 * Set binddn and bindpass with values from the config
	 * file. Do this before the URL extentions so that they
	 * override on a per-block basis.
	 */
	binddn = getSetting("ldapbinddn");
	bindpass = getSetting("ldapbindpass");

	/* check for supported URL extensions:
	 *    bindname=<binddn>      (RFC2255)
	 *    x-bindpass=<bindpass>  (user-specific, allowed by RFC2255)
	 */
	for (ext_i = 0;
	     lud->lud_exts != NULL && lud->lud_exts[ext_i] != NULL;
	     ext_i++) {
		char *key = lud->lud_exts[ext_i];
		char *data;

		/* skip over any 'critical' markers */
		if (*key == '!')
			key++;

		/* find '=' sign (first one is all we care about) */
		data = strchr(key, '=');
		if (data == NULL)
			continue;       /* invalid extension, skip */
		data++;                 /* good extension, get data */

		/* do we recognize the key? */
		if (strncmp(key, "bindname=", 9) == 0) {
			binddn = data;
			sgLogDebug("Extracted binddn: %s", binddn);
		} else if (strncmp(key, "x-bindpass=", 11) == 0) {
			bindpass = data;
			sgLogDebug("Extracted x-bindpass: %s", bindpass);
		}
	}

	/* authenticate to the directory */
	if (ldap_simple_bind_s(ld, binddn, bindpass) != LDAP_SUCCESS) {
		sgLogError("ldap_simple_bind_s failed: %s",
			   ldap_err2string(get_ldap_errno(ld)));
		ldap_unbind(ld);
		ldap_free_urldesc(lud);
		return found;
	}

	/* Perform search */
	if (ldap_search_ext_s(ld, lud->lud_dn, lud->lud_scope, lud->lud_filter,
			      lud->lud_attrs, 0, NULL, NULL, NULL, -1,
			      &ldapresult) != LDAP_SUCCESS) {
		sgLogError("ldap_search_ext_s failed: %s (params: %s, %d, %s, %s)",
			   ldap_err2string(get_ldap_errno(ld)),
			   lud->lud_dn, lud->lud_scope,
			   lud->lud_filter,
			   lud->lud_attrs[0]);

		ldap_unbind(ld);
		ldap_free_urldesc(lud);
		ldap_msgfree(ldapresult);
		return found;
	}

	/* return hash */
	ldapentry = ldap_first_entry(ld, ldapresult);
	if (ldapentry != NULL) {
		/* Use first attribute to get value */
		ldapvals = ldap_get_values(ld, ldapentry, lud->lud_attrs[0]);
		if (ldapvals != NULL) {
			if (*ldapvals != NULL)
				found = 1;
			ldap_value_free(ldapvals);
		}
	}

	/* cleanup */
	ldap_msgfree(ldapresult);
	ldap_unbind(ld);
	ldap_free_urldesc(lud);
	return found;
}

static void freeLDAPMatch(void *o)
{
	sgFree(o);
}

static int ldapUserMatch(void *o, const struct SquidInfo *info)
{
	const char *url = (char *)o;

	if (doLdapSearch(url, info->ident))
		return SOURCE_USER_MATCH;

	return SOURCE_NO_MATCH;
}

struct SourceMatch *newLDAPUserMatch(const char *url)
{
	struct SourceMatch *result = NULL;

	if (!ldap_is_ldap_url(url)) {
		sgLogError("can't parse LDAP url '%s'", url);
		return NULL;
	}

	if ((result = sgNewSourceMatch(SOURCE_USER_MATCH, ldapUserMatch, freeLDAPMatch)) == NULL)
		return NULL;

	result->priv = sgStrdup(url);

	return result;
}

static int ldapIPMatch(void *o, const struct SquidInfo *info)
{
	const char *url = (char *)o;

	if (doLdapSearch(url, info->src))
		return SOURCE_IP_MATCH;

	return SOURCE_NO_MATCH;
}

struct SourceMatch *newLDAPIPMatch(const char *url)
{
	struct SourceMatch *result = NULL;

	sgLogDebug("initialize LDAP IP match with URL %s", url);

	if (!ldap_is_ldap_url(url)) {
		sgLogError("can't parse LDAP url '%s'", url);
		return NULL;
	}

	if ((result = sgNewSourceMatch(SOURCE_IP_MATCH, ldapIPMatch, freeLDAPMatch)) == NULL)
		return NULL;

	result->priv = sgStrdup(url);

	return result;
}

#endif
