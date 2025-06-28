#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/select.h>
#include <curl/curl.h>

#define PROGNAME "mustaine-thrash"
#define VERSION "0.1.0"

enum http_verb_t {
	NONE,
	GET,
	PATCH,
	POST,
};

struct prog_params_t {
	enum http_verb_t verb;
	char *host;
	char *path;
	char *body;
	long delay;
	struct curl_slist *headers;
	int http;
	int times;
	int noverifypeer;
};

void usage(void) {
	fprintf(stderr, PROGNAME " version " VERSION "\n");
	fprintf(stderr, "usage: " PROGNAME " <--get|--patch|--post|--put> <path>\n"
			"\t[--body '<body data>'|--bodyfile <filename>]\n"
			"\t[--delay <delay>] [--header '<name>: <value>'] "
			"[--host <host>]\n"
	      		"\t[--http] [--times <counter>] [--noverifypeer]\n");
}

int handle_request(struct prog_params_t *params) 
{
	CURLM *multi_handle = curl_multi_init();
	int still_running = 0;
	int i;
	char *url = malloc(1024);
	snprintf(url, 1024, "%s://%s%s", params->http?"http":"https", params->host, params->path);
	url[1023] = '\0';


	for(i=0; i<params->times; i++) {
	        struct timeval t;
		t.tv_sec = 0;
	        t.tv_usec = params->delay;
		CURL *easy_handle = curl_easy_init();

		switch(params->verb) {
			case PATCH:
				curl_easy_setopt(easy_handle, 
					CURLOPT_CUSTOMREQUEST, 
					"PATCH");
				break;
			case POST:
				curl_easy_setopt(easy_handle,
					CURLOPT_POST, 1);
				break;
			default:
				break;				
		}

		if (params->body) {
			curl_easy_setopt(easy_handle, CURLOPT_POSTFIELDS, 
					params->body);
		}

		curl_easy_setopt(easy_handle, CURLOPT_VERBOSE, 1);
		curl_easy_setopt(easy_handle, CURLOPT_URL, url);
		curl_easy_setopt(easy_handle, CURLOPT_PATH_AS_IS, 1);
		curl_easy_setopt(easy_handle, CURLOPT_HTTPHEADER, params->headers);
		curl_easy_setopt(easy_handle, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2_0);

		if (params->noverifypeer) 
			curl_easy_setopt(easy_handle, CURLOPT_SSL_VERIFYPEER, 0);
		curl_multi_add_handle(multi_handle, easy_handle);
		curl_multi_perform(multi_handle, &still_running);
	        select(0, NULL, NULL, NULL, &t);
	} 

	do {
		curl_multi_perform(multi_handle, &still_running);
	} while(still_running);

	free(url);

	curl_multi_cleanup(multi_handle);
	return 0;
}

char *load_file(const char *fname) {
	int fd;
	char *map;
	struct stat statbuf;

	fd = open(strdup(optarg), O_RDONLY);
	if (fd == -1) {
		perror(PROGNAME ": could not open() bodyfile");
		return NULL;
	}

	if (fstat(fd, &statbuf) == -1) {
		perror(PROGNAME ": could not fstat() bodyfile");
		close(fd);
		return NULL;
	}

	map = malloc(statbuf.st_size + 1);
	if (!map) {
		perror(PROGNAME ": could not malloc() for bodyfile data");
		close(fd);
		return NULL;
	}

	read(fd, map, statbuf.st_size);
	map[statbuf.st_size] = '\0';
	close(fd);

	return map;
}

int main(int argc, char *argv[]) 
{
	enum http_verb_t got_verb = NONE;
	int got_delay = 0;
	int got_header = 0;
	int got_host = 0;
	int got_http = 0;
	int got_times = 0;
	int got_noverifypeer = 0;
	int got_body = 0;
	int got_bodyfile = 0;

	struct option long_options[] = {
		{ "get", required_argument, (int *) &got_verb, (int) GET },
		{ "delay", required_argument, &got_delay, 1 },
		{ "header", required_argument, &got_header, 1 },
		{ "host", required_argument, &got_host, 1 },
		{ "http", no_argument, &got_http, 1 },
		{ "times", required_argument, &got_times, 1 },
		{ "noverifypeer", no_argument, &got_noverifypeer, 1 },
		{ "patch", required_argument, (int *) &got_verb, (int) PATCH },
		{ "body", required_argument, &got_body, 1 }, 
		{ "post", required_argument, (int *) &got_verb, (int) POST },
		{ "bodyfile", required_argument, &got_bodyfile, 1},
	};

	struct prog_params_t params = { 
		.verb=NONE, .delay=15, .headers=NULL, .host="127.0.0.1", 
		.http=0, .path=NULL, .times=1000, .noverifypeer=0, .body=NULL
       	};
	
	int r = 0;
	int index = 0;

	curl_global_init(CURL_GLOBAL_SSL);

	while((r = getopt_long(argc, argv, "", long_options, &index)) != -1) 
	{
		if (r == '?') {
			exit(1);
		}

		switch(index) {
			case 0: if (params.path) {
					fprintf(stderr, PROGNAME ": only a single HTTP verb is allowed\n");
					exit(1);
				}
				params.path = strdup(optarg);
				params.verb = GET;
				break;
			case 1: params.delay = (int) strtol(optarg, NULL, 10);
				break;
			case 2: params.headers = curl_slist_append(params.headers, strdup(optarg));
				break;
			case 3: params.host = strdup(optarg);
				break;
			case 4: params.http = got_http;
				break;
			case 5: params.times = (int) strtol(optarg, NULL, 10);
				break;
			case 6: params.noverifypeer = got_noverifypeer;
				break;
			case 7: if (params.path) {
					fprintf(stderr, PROGNAME ": only a single HTTP verb is allowed\n");
					exit(1);
				}
				params.path = strdup(optarg);
				params.verb = PATCH;
				break;
			case 8: if (params.body) {
					fprintf(stderr, PROGNAME ": only a single instance of --body or --bodyfile is allowed\n");
					exit(1);
				}
				params.body = strdup(optarg);
				break;
			case 9: if (params.path) {
					fprintf(stderr, PROGNAME ": only a single HTTP verb is allowed\n");
					exit(1);
				}
				params.path = strdup(optarg);
				params.verb = POST;
				break;
			case 10: if (params.body) {
					fprintf(stderr, PROGNAME ": only a single instance of --body or --bodyfile is allowed\n");
					exit(1);
				}
				params.body = load_file(strdup(optarg));
				if (!params.body)
					exit(1);
				break;
			default:
				fprintf(stderr, PROGNAME ": could not understand option\n");
				break;
		}
	}

	if (got_verb == NONE) {
		usage();
		exit(1);
	}

	if (got_noverifypeer && got_http) {
		fprintf(stderr, PROGNAME ": option noverifypeer makes sense "
					 "only with https\n");
		exit(1);
	}

	handle_request(&params);

	curl_global_cleanup();
	return 0;
}
