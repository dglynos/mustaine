#ifndef CHUNKED_H
#define CHUNKED_H 1

extern char mimetype[64];

struct chunked_params {
	int processid;
	int threadid;
	int connfd;
	SSL *ssl;
	struct timeval *timespent;
	char *fname;
	unsigned int delay;
	int postssl;
};

int chunked(struct chunked_params *);
#endif
