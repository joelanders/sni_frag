#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>



class SSLFilter {
    public:
        SSLFilter(SSL_CTX* ctxt,
                  std::string* nread,
                  std::string* nwrite,
                  std::string* aread,
                  std::string* awrite,
                  std::string* hostname);
        virtual ~SSLFilter();

        void update();

    private:
        bool continue_ssl_(int function_return);

        SSL * ssl;
        BIO * rbio;
        BIO * wbio;

        std::string* nread;
        std::string* nwrite;
        std::string* aread;
        std::string* awrite;
};

