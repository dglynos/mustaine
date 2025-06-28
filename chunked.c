#include <stdarg.h>
#include <sys/time.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include "chunked.h"

char mimetype[64];

static void thread_sleep(unsigned int secs) {
	struct timeval t;

	t.tv_sec = secs;
	t.tv_usec = 0;
	select(0, NULL, NULL, NULL, &t);
}

static int write_n_flush(FILE *fout, int postssl, BIO *b, const char *fmt, ...) {
	va_list varargs;
	int ret = 0;

	va_start(varargs, fmt);

	if (postssl) {
		if (BIO_vprintf(b, fmt, varargs) < 0) {
			ret = -1;
			goto exit;
		}
		if (BIO_flush(b) <= 0) {
			ret = -1;
			goto exit;
		}
	} else {
		if (vfprintf(fout, fmt, varargs) < 0) {
			ret = -1;
			goto exit;
		}
		if (fflush(fout) == EOF) {
			ret = -1;
			goto exit;
		}
	}
exit:
	va_end(varargs);
	return ret;
}

int chunked(struct chunked_params *p)
{
	FILE *fh_in, *fh_out;
	struct timeval t1, t2;
	struct stat statbuf;
	size_t bytes_read;
	char timebuf[30];
	BIO *b;
	int ret = 1;
	struct tm thetime;
	time_t now;

	gettimeofday(&t1, NULL);
	if (!(fh_in = fopen(p->fname, "r"))) {
		return 0;
	}
	fstat(fileno(fh_in), &statbuf);

	if (!(fh_out = fdopen(p->connfd, "w"))) {
		ret = 2;
		goto late_exit;
	}

	if (p->postssl) {
		b = BIO_new(BIO_f_ssl());
		BIO_set_ssl(b, p->ssl, BIO_CLOSE);
	}

	now = time(NULL);

	localtime_r(&now, &thetime);
	strftime(timebuf, sizeof(timebuf), "%a, %d %b %Y %T %Z", &thetime);

	if (write_n_flush(fh_out, p->postssl, b, 
		"HTTP/1.1 200 OK\r\n"
		"Content-Type: %s\r\n"
		"Date: %s\r\n"
		"Server: Apache\r\n"
		"Transfer-Encoding: chunked\r\n"
		"\r\n", mimetype, timebuf) < 0) 
	{
		ret = 2;
		goto exit;
	}
	
	for(bytes_read=0; bytes_read<statbuf.st_size; bytes_read++) {
		char c;

		fread(&c, sizeof(char), 1, fh_in);
		if (write_n_flush(fh_out, p->postssl, b, 
				  "1\r\n%c\r\n", c) < 0) 
		{
			ret = 2;
			goto exit;
		}
		thread_sleep(p->delay);
	}

	if (write_n_flush(fh_out, p->postssl, b, "0\r\n\r\n") < 0 ) 
	{
		ret = 2;
	}

exit:
	if (p->postssl) {
		BIO_free_all(b);
	}
late_exit:
	fclose(fh_in);
	gettimeofday(&t2, NULL);
	timersub(&t2, &t1, p->timespent);
	return ret;
}

