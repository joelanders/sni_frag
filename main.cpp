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
    std::string hn2 { "fucking example.com shit" };
    std::size_t found = hn2.find(hostname);
    if (found!=std::string::npos) {
        std::cout << "fucking found" << std::endl;
    }

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
	fd_set fds;
	FD_ZERO(&fds);
	FD_SET(sockfd, &fds);
	while(1) {
		tv.tv_sec = 1;
		tv.tv_usec = 0;
		////////////////////////////////////
		// first check if socket is writable
		// (draining nwrite)
		////////////////////////////////////
		sel_ret = select(sockfd+1, NULL, &fds, NULL, &tv); // wait for writeable
		if (sel_ret < 0) {
			printf("select() failed");
			exit(1);
		}
		if (sel_ret == 0) {
			printf("select() timed out waiting for writable.\n");
		} else {
			// only put one fd in, so we know it's writeable
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

		//////////////////////////////////
		// now check if socket is readable
		// (filling nread)
		//////////////////////////////////
		tv.tv_sec = 1;
		tv.tv_usec = 0;
		sel_ret = select(sockfd+1, &fds, NULL, NULL, &tv); // wait for readable
		if (sel_ret < 0) {
			printf("select() failed");
			exit(1);
		}
		if (sel_ret == 0) {
			printf("select() timed out waiting for readable.\n");
		} else {
			printf("nread.size(): %d\n", nread.size());
			while(1) {
				n = read(sockfd, &readbuf, sizeof(readbuf));
				std::cout << "read from sockfd: " << n << std::endl;
				if (read > 0) {
					size_t cur_size = nread.length();
					nread.resize(cur_size + n);
					std::copy(readbuf, readbuf + n, nread.begin() + cur_size);
				}
				if (static_cast<size_t>(n) != sizeof(readbuf) || n == 0) {
					break;
				}
				if(n < 0) {
					printf("Read error \n");
					break;
				}
			}
			printf("nread.size(): %d\n", nread.size());
		} 
		////////////////////////////// 
		////////////////////////////// 
		////////////////////////////// 
		// XXX aread just grows for now, I never drain it
		ssl_filter.update();
        std::cout << "AREAD" << std::endl;
        std::cout << aread << std::endl;
		sleep(1.0);

	}

    return 0;

}
