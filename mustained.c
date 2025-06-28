#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/wait.h>
#include <errno.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#include <sys/select.h>
#include <pthread.h>
#include <limits.h>
#include <sys/time.h>
#include <sys/mman.h>
#define _GNU_SOURCE         
#include <unistd.h>
#include <sys/syscall.h>
#include <locale.h>
#include "chunked.h"
#include "mime.h"

#define PROGNAME "mustained"
#define VERSION "0.1.0"
/* max LISTENQ is 4096 on Linux 5.4.0 */
#define LISTENQ  4096
#define BUFFSIZE 1024
#define ENDPOINTS_PER_PROCESS 1000

#define libc_fatal(A) do { perror(PROGNAME ": " A); exit(1); } while(0)

#ifndef gettid
#define gettid() syscall(SYS_gettid)
#endif

pid_t *pids;
pthread_t *tids; // filled by each process
void *map;

int postssl = 0;
int accept_count = 0;
int endpoints = 0;
int nprocs = 0;

char chainfile[PATH_MAX+1];
char privkey[PATH_MAX+1];
char chunkedfile[PATH_MAX+1];

enum scenario_t {
	STW, // sitting there waiting
	CHUNKED,
};

enum scenario_t scenario = STW;

struct thread_param_t {
    SSL_CTX *ctx;
    int listenfd;
    int processid;
    int threadid;
};

enum process_state_t {
   PNORMAL,
   TIDS_MALLOC_FAILED,
   PTHREAD_MALLOC_FAILED,
   PTHREAD_ATTR_MALLOC_FAILED,
   PTHREAD_PARAM_MALLOC_FAILED,
   PTHREAD_CREATE_FAILED,
   THREAD_EVENT,
};

struct process_entry_t {
   pid_t pid;
   enum process_state_t state;
   int state_val;
};

enum thread_state_t {
   TNORMAL,
   CLIENT_LANDED,
   SELECT_UNBLOCKED_TIME,
   ACCEPT_FAILED,
   SSL_ACCEPT_FAILED,
   SELECT_FAILED,
};

struct thread_entry_t {
   pid_t tid;
   enum thread_state_t state;
   int state_val;
};

typedef struct sockaddr *SA;
typedef void (*sighandler_t)(int);

void set_child_id(int processid, pid_t pid) {
   struct process_entry_t *entries = (map + sizeof(int));
   entries[processid].pid = pid;
}

void set_child_state(int processid, enum process_state_t state, int val) {
   struct process_entry_t *entries = (map + sizeof(int));
   entries[processid].state = state;
   entries[processid].state_val = val;
}

void set_thread_id(int processid, int threadid, pid_t tid) {
   struct thread_entry_t *entries = (map + ((int *) map)[0]);
   entries[(processid * ENDPOINTS_PER_PROCESS) + threadid].tid = tid;
}

void set_thread_state(int processid, int threadid, enum thread_state_t state, 
   int val) 
{
   struct thread_entry_t *entries = (map + ((int *) map)[0]);
   entries[(processid * ENDPOINTS_PER_PROCESS) + threadid].state = state;
   entries[(processid * ENDPOINTS_PER_PROCESS) + threadid].state_val = val;
   set_child_state(processid, THREAD_EVENT, threadid);
}

void dump_map(void) {
   int p;
   struct process_entry_t *pentries = (map + sizeof(int));
   struct thread_entry_t *tentries = (map + ((int *) map)[0]);
   struct thread_entry_t *tentry;

   fputc('[', stdout);

   for (p=0; p<nprocs; p++) {
      switch(pentries[p].state) {
         case TIDS_MALLOC_FAILED:
            fputc('1', stdout);
            break;
         case PTHREAD_MALLOC_FAILED:
            fputc('2', stdout);
            break;
         case PTHREAD_ATTR_MALLOC_FAILED:
            fputc('3', stdout);
            break;
         case PTHREAD_PARAM_MALLOC_FAILED:
            fputc('4', stdout);
            break;
         case PTHREAD_CREATE_FAILED:
            fputc('T', stdout);
            break;
         case THREAD_EVENT:
            tentry = &tentries[(p*ENDPOINTS_PER_PROCESS)+pentries[p].state_val];
            switch(tentry->state) {
               case CLIENT_LANDED:
                  fprintf(stdout, "C%iC", pentries[p].state_val);
                  break;
               case SELECT_UNBLOCKED_TIME:
                  fprintf(stdout, "U%i/%iU", pentries[p].state_val, tentry->state_val);
                  break;
               case ACCEPT_FAILED:
                  fprintf(stdout, "A%i/%iA", pentries[p].state_val, tentry->state_val);
                  break;
               case SSL_ACCEPT_FAILED:
                  fprintf(stdout, "S%i/%iS", pentries[p].state_val, tentry->state_val);
                  break;
               case SELECT_FAILED:
                  fprintf(stdout, "s%i/%is", pentries[p].state_val, tentry->state_val);
                  break;
               default:
                  fprintf(stdout, "?%i/%i?", pentries[p].state_val, tentry->state_val);
                  break;
            }
	         break;
         default:
            fputc('*', stdout);
      }
   }
      
   fprintf(stdout, "]\n");
   fflush(stdout);
}

void dump_legend(void) {
   fprintf(stdout, "Legend -------------------------------------------------------------------------\n");
   fprintf(stdout, "1-4\t\t\tmalloc failures\n");
   fprintf(stdout, "T\t\t\tpthread_create failure\n");
   fprintf(stdout, "*\t\t\tno news, good news\n");
   fprintf(stdout, "C[#thread]C\t\ta client landed on our socket\n");
   fprintf(stdout, "U[#thread/#secs]U\ttime it took for client to drop connection\n");
   fprintf(stdout, "A[#thread/#errno]A\taccept failure on socket\n");
   fprintf(stdout, "S[#thread/#errno]S\tSSL_accept failure on socket\n");
   fprintf(stdout, "s[#thread/#errno]s\tselect failure on socket\n");
   fprintf(stdout, "--------------------------------------------------------------------------------\n");
}

void sig_chld(int signo)   /* handler for SIGCHLD */
{
   int stat;
   int pid;
   while ((pid = waitpid(-1, &stat, WNOHANG)) > 0) {
      fprintf(stderr, "process %i exited with status %i!\n", pid, stat);
   }
}

SSL_CTX *create_context()
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = TLS_server_method();
    ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror(PROGNAME ": unable to create SSL context");
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    return ctx;
}

int configure_context(SSL_CTX *ctx)
{
    /* Set the key and cert */
    if (SSL_CTX_use_certificate_chain_file(ctx, chainfile) <= 0) {
        ERR_print_errors_fp(stderr);
        return 0;
    }
/*
   if (SSL_CTX_use_certificate_file(ctx, "cert.pem", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        return 0;
    }
*/
    if (SSL_CTX_use_PrivateKey_file(ctx, privkey, SSL_FILETYPE_PEM) <= 0 ) {
        ERR_print_errors_fp(stderr);
        return 0;
    }
    return 1;
}

int stw(int processid, int threadid, int fd, SSL *ssl, 
	struct timeval *timespent) 
{
   int nready;
   fd_set rset, allset;
   struct timeval timeleft;
   struct timeval timeout = { .tv_sec = 8 * 60 * 60, .tv_usec = 0 };

   timeleft = timeout;
   
   FD_ZERO(&allset);
   FD_SET(fd, &allset);

   rset = allset;
 
   nready = select(fd + 1, &rset, NULL, NULL, &timeleft);
   if (nready == -1) {
      set_thread_state(processid, threadid, SELECT_FAILED, (int) errno);
      return 0;
   }

   timersub(&timeout, &timeleft, timespent);
   set_thread_state(processid, threadid, SELECT_UNBLOCKED_TIME, (int) timespent->tv_sec);

   return 1;
}

int req_proc(int processid, int threadid, int fd, SSL *ssl)   /* process requests */
{
   int nread, ret;
   char buffer[BUFFSIZE];
   struct timeval timespent;
  
   if (postssl) {
	   nread = SSL_read(ssl, buffer, BUFFSIZE);
   } else {
	   nread = read(fd, buffer, BUFFSIZE);
   }

   if (nread <= 0) { // at present we don't log read errors and early droppers
	return 0;
   }

   if (nread == BUFFSIZE)
	   buffer[BUFFSIZE-1]= '\0';
   else
	   buffer[nread] = '\0';
//   fprintf(stderr, "[%i/%i] received: %s\n", processid, threadid, buffer);

   if (scenario == STW)
	   ret = stw(processid, threadid, fd, ssl, &timespent);
   else {
	   struct chunked_params p = {
		   .processid = processid,
		   .threadid = threadid,
		   .connfd = fd,
		   .ssl = ssl,
		   .timespent = &timespent,
		   .fname = "file.png",
		   .delay = 1,
		   .postssl = postssl
	   };
	   ret = chunked(&p);
   }

   return ret;
}

void *routine(void *tparam) {
   struct thread_param_t *_tparam;

   _tparam = (struct thread_param_t *) tparam;
   set_thread_id(_tparam->processid, _tparam->threadid, (pid_t) gettid());
   for(;;) { 
      socklen_t addrlen;
      struct sockaddr_in cliaddr;
      SSL *ssl;
      int connfd;
   
      bzero(&cliaddr, sizeof(cliaddr));
      addrlen = sizeof(cliaddr);

      connfd = accept(_tparam->listenfd, (SA) &cliaddr, &addrlen);
      if (connfd < 0) {
         if (errno == EINTR) continue;

         set_thread_state(_tparam->processid, _tparam->threadid, ACCEPT_FAILED, (int) errno);
         return NULL;
      }

      set_thread_state(_tparam->processid, _tparam->threadid, CLIENT_LANDED, 0);
      
      if (postssl) {
         int ret;
	      ssl = SSL_new(_tparam->ctx);
	      SSL_set_fd(ssl, connfd);
         ret = SSL_accept(ssl);
         if (ret <= 0) {
            set_thread_state(_tparam->processid, _tparam->threadid, SSL_ACCEPT_FAILED, ret);
            SSL_free(ssl);
            close(connfd);
            return NULL;
         }
      }

      req_proc(_tparam->processid, _tparam->threadid, connfd, ssl);

      if (postssl) {
	SSL_shutdown(ssl);
      	SSL_free(ssl);
      }

      close(connfd);
   }
   return NULL;
}

pthread_t spawn_thread(int processid, int threadid, int listenfd, SSL_CTX *ctx)
{
   pthread_t *thread;   
   pthread_attr_t *threadattr;
   struct thread_param_t *tparam;

   thread = malloc(sizeof(pthread_t));
   if (!thread) {
      set_child_state(processid, PTHREAD_MALLOC_FAILED, threadid);
      goto e_thread;
   }

   threadattr = malloc(sizeof(pthread_attr_t));
   if (!threadattr) {
      set_child_state(processid, PTHREAD_ATTR_MALLOC_FAILED, threadid);
      goto e_threadattr;
   }
   pthread_attr_init(threadattr);
   pthread_attr_setstacksize(threadattr, PTHREAD_STACK_MIN + 8192);
         
   tparam = malloc(sizeof(tparam));
   if (!tparam) {
      set_child_state(processid, PTHREAD_PARAM_MALLOC_FAILED, threadid);
      goto e_tparam;
   }

   tparam->listenfd = listenfd;
   tparam->ctx = ctx;
   tparam->processid = processid;
   tparam->threadid = threadid;
   
   if (!pthread_create(thread, threadattr, routine, tparam))
      return *thread;
   
   set_child_state(processid, PTHREAD_CREATE_FAILED, threadid);
   free(tparam);

   e_tparam:     free(threadattr);
   e_threadattr: free(thread);
   e_thread:     return 0;
}

pid_t spawn_process(int id, int listenfd, int nthreads, SSL_CTX *ctx)
{      /* Makes new child and handles client */
   pid_t pid;   
   int i;
   struct sigaction sigact;
      
   pid = fork();

   if (pid > 0) return pid; // return pid to parent
   if (pid < 0) return 0; // signal error to parent

   // child code
   close(0); // close stdin
   // close(1); close(2); // close stdin, stdout, stderr
  
   // early socket disconnects should not be fatal
   sigact.sa_handler = SIG_IGN;
   sigaction(SIGPIPE, &sigact, NULL);

   set_child_id(id, getpid());
  
   tids = malloc(nthreads * sizeof(pthread_t));
   if (!tids) {
      set_child_state(id, TIDS_MALLOC_FAILED, 0);
      exit(1);
   }
   
   for (i=0; i<nthreads; i++) {
      tids[i]=spawn_thread(id, i, listenfd, ctx);
      if (!tids[i]) {
         exit(1);
      }
   }
   
   pause();
   exit(0);
}

int parse_ssl_args(const char *arg, char *chainfile, size_t chainlen, 
		 char *privkey, size_t privkeylen) 
{
	const char *p = arg;
	char *chain_end = NULL;

	p += 4;

	strncpy(chainfile, p, chainlen);
	chainfile[chainlen-1] = '\0';
	chain_end = index(chainfile, ':');
	if (!chain_end) {
		fprintf(stderr, PROGNAME ": no ':' character specified at end of chainfile path\n");
		return -1;
	}

	*chain_end = '\0';
	p = chain_end + 1;

	if (!(*p)) {
		fprintf(stderr, PROGNAME ": no SSL private key path provided\n");
		return -1;
	}

	strncpy(privkey, p, privkeylen);
	privkey[privkeylen-1] = '\0';

	return 0;
}

int parse_chunked_file(const char *arg, char *fname, size_t fname_len) 
{
	const char *p = arg;

	// skip over 'chunked:'
	p += 8;

	if (!(*p))
		return -1;

	strncpy(fname, p, fname_len);
	fname[fname_len-1] = '\0';

	return 0;
}

void usage(void) {
	fprintf(stderr, PROGNAME " version " VERSION "\n");
	fprintf(stderr, "usage: " PROGNAME " <port> <nossl|ssl:pubchain:privkey> <#endpoints> <stw|chunked:file>\n");
	fprintf(stderr, "\tpubchain: path to file containing SSL chain of certificates\n");
	fprintf(stderr, "\tprivkey: path to file containing SSL private key\n");
	fprintf(stderr, "\tfile: path to file whose contents will be delivered with chunked encoding\n");
}

int main(int argc, char *argv[])
{
   int i, listenfd, procdatalen, threaddatalen, nthreads_needed;
   struct sockaddr_in servaddr;
   unsigned short port = 0;
   SSL_CTX *ctx = NULL;

   if (argc != 5) {
	   usage();
	   exit(1);
   }

   port = (unsigned short) strtoul(argv[1], NULL, 10);

   if (!strncmp(argv[2], "ssl:", 4)) {
      postssl = 1;
      if (parse_ssl_args(argv[2], chainfile, sizeof(chainfile), privkey, sizeof(privkey))) 
      {
		usage();
		exit(1);	
      }
   }

   if (!strncmp(argv[4], "chunked:", 8)) {
      scenario = CHUNKED;
   }

   if (parse_chunked_file(argv[4], chunkedfile, sizeof(chunkedfile))) 
   {
	   usage();
	   exit(1);
   }

   if (get_mime(chunkedfile, mimetype, sizeof(mimetype))) 
   {
	   fprintf(stderr, PROGNAME ": could not determine mimetype for file '%s'\n", chunkedfile);
	   exit(1);
   }


   setlocale(LC_ALL, "C");

   endpoints = strtoul(argv[3], NULL, 10);
   if (endpoints == 0 || (endpoints == ULONG_MAX && errno == ERANGE))
      libc_fatal("#endpoints must be a positive number");

   nprocs = (endpoints / ENDPOINTS_PER_PROCESS) + ((endpoints % ENDPOINTS_PER_PROCESS)?1:0);
   
   if (postssl) {
	   ctx = create_context();
      if (!ctx)
         exit(1);
	   if (!configure_context(ctx))
         exit(1);
   }
   
   if ((listenfd = socket (AF_INET, SOCK_STREAM, 0)) < 0)
      libc_fatal("running without root on low privileged port?");
      
   bzero(&servaddr, sizeof(servaddr));
   servaddr.sin_family = AF_INET;
   servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
   servaddr.sin_port = htons(port);
   
   if (bind(listenfd, (SA) &servaddr, sizeof(servaddr)) < 0)
      libc_fatal("bind error");
   
   if (listen(listenfd, LISTENQ) < 0)
      libc_fatal("listen error");

   if (!(pids = calloc(nprocs, sizeof(pid_t))))
      libc_fatal("calloc pids failed");

   signal(SIGCHLD, (sighandler_t) sig_chld);

   procdatalen = nprocs * sizeof(struct process_entry_t);
   threaddatalen = endpoints * sizeof(struct thread_entry_t);

   map = mmap(NULL, sizeof(procdatalen) + procdatalen + threaddatalen,
    PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
   if (map == MAP_FAILED) {
      libc_fatal("mmap failed");
   }

   *((int *) map) = procdatalen;

   fprintf(stderr, PROGNAME ": spawning %d process(es) [max %d endpoints each]\n", nprocs, ENDPOINTS_PER_PROCESS);

   nthreads_needed = endpoints;
   
   for (i=0 ; i<nprocs; i++) {
      int nthreads_this_round = (nthreads_needed > ENDPOINTS_PER_PROCESS)? ENDPOINTS_PER_PROCESS: nthreads_needed;
      if (!(pids[i] = spawn_process(i, listenfd, nthreads_this_round, ctx))) {
         fprintf(stderr, PROGNAME ": failure while initiating process #%i.\n", i+1);
         fprintf(stderr, PROGNAME ": please standby for program exit\n");
         for (i=0; i<nprocs; i++) {
            if (pids[i])
               kill(pids[i], SIGTERM);
         }
         exit(1);
      }
      nthreads_needed -= nthreads_this_round;
   }

   dump_legend();
   /* Everything is done by the children */   
   for (;;) { sleep(1); dump_map();}

   return 0;
}
