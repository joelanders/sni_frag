#include <iostream>
#include <string>
#include "openssl_filter.hpp"

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>

#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h> 
#include <sys/time.h>

void print_timer(struct timeval tval_start) {
    struct timeval tval_current, tval_diff;
    gettimeofday(&tval_current, NULL);
    timersub(&tval_start, &tval_current, &tval_diff);
    printf("Time elapsed: %ld.%06ld\n", (long int)tval_diff.tv_sec, (long int)tval_diff.tv_usec);
}

int main(int argc, char* argv[]) {
	if (argc != 3) {
		printf("Usage: %s <hostname> <ip>\n",argv[0]);
		printf("Example: example.com 93.184.216.34\n");
		printf("(I'm skipping DNS resolution for simplicity ;p)\n");
		return 1;
	} 

    std::string hostname { argv[1] };
    std::cout << "hostname: " << hostname << std::endl;
    std::cout << "hostname.length(): " << hostname.length() << std::endl;

    std::string nread, nwrite, aread, awrite;
	SSL_CTX* ctx = SSL_CTX_new(SSLv23_method()); //XXX don't ignore errors
	if (ctx == NULL) {
		printf("failed to make context\n");
		exit(1);
	}
	SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL); //XXX probably want to verify eventually

	SSLFilter ssl_filter = SSLFilter(ctx, &nread, &nwrite, &aread, &awrite, &hostname);

	int sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0)
	{
		printf("socket() failed");
		return 1;
	} 

	struct sockaddr_in serv_addr; 
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(443); //XXX assuming this for now

	if (inet_pton(AF_INET, argv[2], &serv_addr.sin_addr) <= 0) {
		printf("inet_pton() failed");
		return 1;
	} 

	if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
       printf("connect() failed");
       return 1;
    } 

	//char req[] = "GET /\r\n\r\n";
	//write(sockfd, req, sizeof(req));
	awrite = "GET /index.html HTTP/1.1\r\nHost: ";
	awrite += hostname;
	awrite += "\r\n\r\n";
	//std::copy(&req, &req+sizeof(req), awrite);
	printf("nwrite.size(): %d\n", nwrite.size());
	printf("awrite.size(): %d\n", awrite.size());
	ssl_filter.update();
	printf("nwrite.size(): %d\n", nwrite.size());
	printf("awrite.size(): %d\n", awrite.size());

	char readbuf[1024]; //XXX put on heap

    struct timeval tv;
	int sel_ret;
	int n;
	bool stop_reading = false;
	bool stop_writing = false;
	fd_set rfds, wfds;

    struct timeval tval_start;
    gettimeofday(&tval_start, NULL);

	while(1) {
        printf("TOP OF WHILE LOOP\n");
        print_timer(tval_start);
        FD_ZERO(&rfds);
        FD_ZERO(&wfds);
        if (!stop_reading) {
            FD_SET(sockfd, &rfds);
        }
        if (!nwrite.empty() && !stop_writing) {
            FD_SET(sockfd, &wfds);
        }

		tv.tv_sec = 1;
		tv.tv_usec = 0;

		printf("BLOCKING ON SELECT\n");
        print_timer(tval_start);
		sel_ret = select(sockfd+1, &rfds, &wfds, NULL, &tv);
		if (sel_ret < 0) {
			printf("select() failed");
			break;
		}
		if (sel_ret == 0) {
			printf("select() timed out.\n");
			break;
		}
        if (FD_ISSET(sockfd, &wfds)) {
            printf("WRITABLE\n");
            // only put one fd in, so we know it's writeable
            printf("awrite.size(): %d\n", awrite.size());
            printf("nwrite.size(): %d\n", nwrite.size());

            //XXX clean this up
            std::size_t found = nwrite.find(hostname);
            if (found!=std::string::npos) {
                std::cout << "$$$$$$ found plaintext hostname; hacking planet $$$$$$$$$" << std::endl;
                n = write(sockfd, nwrite.c_str(), found+3);
                std::cout << "written to sockfd: " << n << std::endl;
                if (n > 0) {
                    nwrite.erase(0, n);
                }
                sleep(0.5);
            }

            n = write(sockfd, nwrite.c_str(), nwrite.length());
            std::cout << "written to sockfd: " << n << std::endl;
            if (n > 0) {
                nwrite.erase(0, n);
            }
            printf("nwrite.size(): %d\n", nwrite.size());
        }
        if (FD_ISSET(sockfd, &rfds)) {
            printf("READABLE\n");
            printf("nread.size(): %d\n", nread.size());
            while(1) {
                n = read(sockfd, &readbuf, sizeof(readbuf));
                std::cout << "read from sockfd: " << n << std::endl;
                if (read > 0) {
                    size_t cur_size = nread.length();
                    nread.resize(cur_size + n);
                    std::copy(readbuf, readbuf + n, nread.begin() + cur_size);
                }
                if (static_cast<size_t>(n) != sizeof(readbuf)) {
                    break;
                }
                if (n == 0) {
                    stop_reading = true;
                    break;
                }
                if(n < 0) {
                    printf("Read error \n");
                    break;
                }
            }
            printf("nread.size(): %d\n", nread.size());
        }

		ssl_filter.update();
		if (awrite.size() == 0 && nwrite.size() == 0) {
		    stop_writing = true;
        }
        if (stop_reading && stop_writing) {
            break;
        }

	}
    std::cout << "AREAD" << std::endl;
    std::cout << aread << std::endl;

    return 0;

}
