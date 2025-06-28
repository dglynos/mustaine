# mustaine

This repository holds a set of tools to measure timeouts in requests made
by web applications backends. 

When a web application is vulnerable to a Server Side Request Forgery (SSRF)
issue and the relevant request made by the web application uses a long 
timeout value, it is possible for an attacker to abuse the timeout and 
create a file descriptor exhaustion condition on the web application. 
By placing multiple calls to the vulnerable (to SSRF) endpoint, the attacker
will eventually deplete the file descriptors available to the web application
process(es) and will bring the application to a Denial of Service condition.

This repository introduces two tools (`mustaine-thrash` and `mustained`) 
to measure timeouts in requests made by web application backends.

## Build

To build the tools on a Debian system:

```
# apt-get update
# apt-get install -y build-essential gcc make libssl-dev libmagic-dev libcurl4-openssl-dev
$ make
```

For convenience, a Dockerfile is also provided.
