#include <magic.h>
#include <stdio.h>
#include <string.h>

int get_mime(const char *fname, char *mimetype, size_t mimetype_len) 
{
	magic_t cookie;
	const char *descr;

	cookie = magic_open(MAGIC_MIME_TYPE);

	magic_load(cookie, NULL);

	descr = magic_file(cookie, fname);
	if (!descr) {
		return -1;
	}

	strncpy(mimetype, descr, mimetype_len);
	mimetype[mimetype_len-1] = '\0';
	magic_close(cookie);

	return 0;
}
