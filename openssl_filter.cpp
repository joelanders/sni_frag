// based on https://funcptr.net/2012/04/08/openssl-as-a-filter-(or-non-blocking-openssl)/
#include <stdexcept>

#include "openssl_filter.hpp"
#include <iostream>

SSLFilter::SSLFilter(SSL_CTX* ctxt, 
                     std::string* nread, 
                     std::string* nwrite,
                     std::string* aread,
                     std::string* awrite,
                     std::string* hostname)
                      :
                     nread(nread), 
                     nwrite(nwrite), 
                     aread(aread), 
                     awrite(awrite) {

    rbio = BIO_new(BIO_s_mem());
    wbio = BIO_new(BIO_s_mem());

    ssl = SSL_new(ctxt);
	if (ssl == NULL) {
		std::cout << "ssl_new() failed" << std::endl;
		exit(-1);
	}

	//XXX
    //SSL_set_accept_state(ssl);
    SSL_set_connect_state(ssl);
    SSL_set_bio(ssl, rbio, wbio);
    int success = SSL_set_tlsext_host_name(ssl, hostname->c_str());
    printf("sni success: %d\n", success);
}

SSLFilter::~SSLFilter() {
    SSL_free(ssl);
}

// XXX ought we to specify FilterDirection?
//void SSLFilter::update(Filter::FilterDirection) {
void SSLFilter::update() {
	std::cout << "update()" << std::endl;
    // If we have data from the network to process, put it the memory BIO for OpenSSL
    if (!nread->empty()) {
		std::cout << "SSLFilter: nread->size(): " << nread->size() << std::endl;
        int written = BIO_write(rbio, nread->c_str(), nread->length());
		std::cout << "written to BIO: " << written << std::endl;
        if (written > 0) {
            nread->erase(0, written);
		}
		std::cout << "SSLFilter: nread->size(): " << nread->size() << std::endl;
    }

    // If the application wants to write data out to the network, process it with SSL_write
    if (!awrite->empty()) {
		std::cout << "SSLFilter: awrite->size(): " << awrite->size() << std::endl;
        int written = SSL_write(ssl, awrite->c_str(), awrite->length());
		std::cout << "SSLFilter: written to ssl: " << written << std::endl;

        if (!continue_ssl_(written)) {
            throw std::runtime_error("An SSL error occured.");
        }

        if (written > 0) {
            awrite->erase(0, written);
        }
		std::cout << "SSLFilter: awrite->size(): " << awrite->size() << std::endl;
    }

    // Read data for the application from the encrypted connection and place it in the string for the app to read
    while (1) {
		std::cout << "SSLFilter: filling aread" << std::endl;
		std::cout << "SSLFilter: aread->size(): " << aread->size() << std::endl;
        char *readto = new char[1024];
        int read = SSL_read(ssl, readto, 1024);
		std::cout << "SSLFilter: read from ssl: " << read << std::endl;

        if (!continue_ssl_(read)) {
            delete readto;
            throw std::runtime_error("An SSL error occured.");
        }

        if (read > 0) {
            size_t cur_size = aread->length();
            aread->resize(cur_size + read);
            std::copy(readto, readto + read, aread->begin() + cur_size);
        }

        delete readto;

        if (static_cast<size_t>(read) != 1024 || read == 0) break;
    }
    std::cout << "SSLFilter: aread->size(): " << aread->size() << std::endl;

    // Read any data to be written to the network from the memory BIO and copy it to nwrite
    while (1) {
		std::cout << "SSLFilter: filling nwrite" << std::endl;
		std::cout << "SSLFilter: nwrite->size(): " << nwrite->size() << std::endl;
        char *readto = new char[1024];
        int read = BIO_read(wbio, readto, 1024);
		std::cout << "SSLFilter: read from bio: " << read << std::endl;

        if (read > 0) {
            size_t cur_size = nwrite->length();
            nwrite->resize(cur_size + read);
            std::copy(readto, readto + read, nwrite->begin() + cur_size);
        }

        delete readto;

        if (static_cast<size_t>(read) != 1024 || read == 0) break;
    }
    std::cout << "SSLFilter: nwrite->size(): " << nwrite->size() << std::endl;
}

bool SSLFilter::continue_ssl_(int function_return) {
    int err = SSL_get_error(ssl, function_return);
	char desc[120];

	if (err != SSL_ERROR_NONE) {
		ERR_error_string(err, desc);
		std::cout << "ssl error: " << desc << std::endl;
        ERR_print_errors_fp(stdout);
	}

    if (err == SSL_ERROR_NONE || err == SSL_ERROR_WANT_READ) {
        return true;
    }

    if (err == SSL_ERROR_SYSCALL) {
        ERR_print_errors_fp(stderr);
        perror("syscall error: ");
        return false;
    }

    if (err == SSL_ERROR_SSL) {
        ERR_print_errors_fp(stderr);
        return false;
    }
    return true;
}

