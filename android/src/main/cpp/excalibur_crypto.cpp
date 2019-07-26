#include <string>
#include <iostream>
#include <memory>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/evp.h>
#include <openssl/bn.h>

namespace string
{
    static std::string replace( std::string subject, const std::string & search, const std::string & replace )
    {
        size_t pos = 0;
        while( (pos = subject.find(search, pos)) != std::string::npos )
        {
            subject.replace(pos, search.length(), replace);
            pos += replace.length();
        }
        
        return subject;
    }
}

namespace crypto
{
    const char * HEXADECIMALS = "0123456789ABCDEF";
    
    inline uint8_t hex_to_byte( uint8_t data )
    {
        if( data >= '0' && data <= '9' )
        {
            return data - '0';
        }
        
        if( data >= 'A' && data <= 'F' )
        {
            return data - 'A' + 10;
        }
        
        if( data >= 'a' && data <= 'f' )
        {
            return data - 'a' + 10;
        }
        
        return 0;
    }
    
    enum data_type { STRING, HEX, BASE64 };
    
    data_type type( std::string format )
    {
        if( format == "hex" )
        {
            return HEX;
        }
        else if( format == "base64" )
        {
            return BASE64;
        }
        
        return STRING;
    }
    
    struct buffer
    {
        buffer( size_t length ): length(length)
        {
            data = (uint8_t *) malloc( length * sizeof(uint8_t) );
            memset(data, 0, length);
        }
        
        buffer( const std::string & str, data_type type = STRING )
        {
            if( type == STRING )
            {
                length = str.length();
                data = (uint8_t *) malloc( length * sizeof(uint8_t) );
                memcpy( data, str.data(), length );
            }
            else if( type == HEX )
            {
                length = str.length() / 2;
                data = (uint8_t *) malloc( length * sizeof(uint8_t) );
                
                for( size_t i = 0; i < length; ++i )
                {
                    data[i] = hex_to_byte( str[2*i] ) * 16 + hex_to_byte( str[2*i+1] );
                }
            }
            else if( type == BASE64 )
            {
                BIO *b64, *bmem;
                
                length = str.length();
                data = (uint8_t *) malloc( length * sizeof(uint8_t) );
                memset(data, 0, length);
                
                b64 = BIO_new(BIO_f_base64());
                bmem = BIO_new_mem_buf( str.data() , (int)str.length() );
                bmem = BIO_push(b64, bmem);
                
                BIO_set_flags(bmem, BIO_FLAGS_BASE64_NO_NL);
                length = BIO_read( bmem, data, (int)length );
                
                BIO_free_all(bmem);
            }
        }
        
        buffer( const buffer & buf )
        {
            length = buf.length;
            data = (uint8_t *) malloc( length * sizeof(uint8_t) );
            memcpy(data, buf.data, length);
        }
        
        buffer & operator=( const buffer & buf )
        {
            length = buf.length;
            data = (uint8_t *) malloc( length * sizeof(uint8_t) );
            memcpy(data, buf.data, length);
            
            return *this;
        }
        
        ~buffer()
        {
            if( data ){ free(data); }
        }
        
        std::string string()
        {
            return std::string( (const char *)data, length );
        }
        
        std::string hex()
        {
            std::string hex;
            
            for( size_t i = 0; i < length; ++i )
            {
                hex += ( data[i] / 16 > 9 ? 'A' + data[i] / 16 - 10 : '0' + data[i] / 16 );
                hex += ( data[i] % 16 > 9 ? 'A' + data[i] % 16 - 10 : '0' + data[i] % 16 );
            }
            
            return hex;
        }
        
        std::string str( data_type type )
        {
            if( type == HEX )
            {
                return hex();
            }
            else if( type == BASE64 )
            {
                return base64();
            }
            
            return string();
        }
        
        std::string base64()
        {
            BIO * bio, * b64;
            BUF_MEM * buffer_ptr;
            
            b64 = BIO_new(BIO_f_base64());
            bio = BIO_new(BIO_s_mem());
            bio = BIO_push(b64, bio);
            
            BIO_write(bio, (const char *)data, (int)length);
            BIO_flush(bio);
            BIO_get_mem_ptr(bio, &buffer_ptr);
            BIO_set_close(bio, BIO_NOCLOSE);
            
            std::string base64( buffer_ptr->data, buffer_ptr->length );
            
            BIO_free_all(bio);
            BUF_MEM_free(buffer_ptr);
            
            return base64;
        }
        
        unsigned char * uchar()
        {
            return (unsigned char *)data;
        }
        
        uint8_t * data;
        size_t length;
    };
    
    static std::string sha512( const std::string & data )
    {
        buffer buff(data, STRING);
        buffer hash(SHA512_DIGEST_LENGTH);
        
        SHA512_CTX ctx;
        SHA512_Init(&ctx);
        SHA512_Update(&ctx, buff.data, buff.length);
        SHA512_Final(hash.data, &ctx);
        
        return hash.hex();
    }
    
    static std::string sha256( const std::string & data )
    {
        buffer buff(data, STRING);
        buffer hash(SHA256_DIGEST_LENGTH);
        
        SHA256_CTX ctx;
        SHA256_Init(&ctx);
        SHA256_Update(&ctx, buff.data, buff.length);
        SHA256_Final(hash.data, &ctx);
        
        return hash.hex();
    }
    
    static std::string pbkdf2( const std::string & pass, const std::string & salt, int iterations )
    {
        buffer hash(SHA256_DIGEST_LENGTH);
        
        PKCS5_PBKDF2_HMAC((const char *)pass.c_str(), (int)pass.length(), (const unsigned char *)salt.c_str(), (int)salt.length(), iterations, EVP_sha256(), SHA256_DIGEST_LENGTH, hash.data);
        
        return hash.hex();
    }
}

class client_certificates
{
  public:
    
    client_certificates( std::string & ca, std::string & public_key, std::string & private_key, std::string & passphrase )
    :
        ca(ca),
        public_key(public_key),
        private_key(private_key),
        passphrase(passphrase)
    {
    }
    
  public:
    
    static int cb(char *buf, int size, int rwflag, void *u)
    {
        auto pass = (std::string*)u;
        auto ii = pass->length();
        
        for( decltype(ii) i = 0; i < ii; ++i ){ buf[i] = (*pass)[i]; }
        
        return (int)pass->length();
    }
    
  private:
    
    std::string ca;
    std::string public_key;
    std::string private_key;
    std::string passphrase;
};

class excalibur_crypto_openssl
{
  public:
    
    static std::string aes_gcm_decrypt( const std::string & key, const std::string & encrypted, const std::string & auth, const std::string & iv_in )
    {
        std::string ret;
        
        if( encrypted.length() <= 32 )
        {
            return ret;
        }
        
        crypto::buffer iv(12);
        memcpy(iv.data, iv_static, 12);
        
        if( iv_in != "" )
        {
            std::string iv_sha = crypto::sha256(iv_in);
            
            if( iv_sha.length() >= 24 )
            {
                iv = crypto::buffer(iv_sha, crypto::HEX);
            }
        }
        
        uint32_t data_len = (uint32_t)(encrypted.length() - 32);
        
        crypto::buffer key_bin(crypto::sha256(key), crypto::HEX);
        crypto::buffer auth_tag(encrypted.substr(data_len, 32), crypto::HEX);
        crypto::buffer data(encrypted.substr(0, data_len), crypto::HEX);
        crypto::buffer out_buff_bin(data_len);
        
        int result = excalibur_crypto_openssl::aes_gcm_decrypt(data.uchar(), (int)(data.length), (unsigned char *)auth.c_str(), (int)auth.length(), auth_tag.uchar(), key_bin.uchar(), iv.uchar(), (int)iv.length, out_buff_bin.uchar());
        
        if( result >= 0 )
        {
            ret = out_buff_bin.string();
        }
        
        return ret;
    }
    
    static std::string aes_gcm_encrypt( const std::string & key, const std::string & data, const std::string & auth, const std::string & iv_in )
    {
        crypto::buffer iv(12);
        memcpy(iv.data, iv_static, 12);
        
        if( iv_in != "" )
        {
            std::string iv_sha = crypto::sha256(iv_in);
            
            if( iv_sha.length() >= 24 )
            {
                iv = crypto::buffer(iv_sha, crypto::HEX);
            }
        }
        
        crypto::buffer key_bin(crypto::sha256(key), crypto::HEX);
        crypto::buffer out_buff_bin((uint32_t)data.length());
        crypto::buffer auth_tag(16);
        
        excalibur_crypto_openssl::aes_gcm_encrypt((unsigned char *)data.c_str(), (int)data.length(), (unsigned char *)auth.c_str(), (int)auth.length(), key_bin.uchar(), iv.uchar(), (int)iv.length, out_buff_bin.uchar(), auth_tag.uchar());
        
        std::string auth_tag_hex = auth_tag.hex();
        std::string data_hex = out_buff_bin.hex();
        
        std::string out = data_hex;
        out.append(auth_tag_hex);
        
        if( auth == "secret" )
        {
            crypto::buffer result(out, crypto::HEX);
            result.length = (size_t)out.length()/2;
            out = result.base64();
        }
        
        return out;
    }
    
    static std::string public_encrypt( const std::string & cert, const std::string & data, const std::string & format )
    {
        RSA * public_rsa = excalibur_crypto_openssl::create_public_rsa(cert.c_str());
        
        if( public_rsa != NULL )
        {
            crypto::buffer encrypted(data, crypto::type(format));
            
            int rsa_len = RSA_size(public_rsa);
            crypto::buffer enc_message(rsa_len);
            
            enc_message.length = RSA_public_encrypt((int)encrypted.length, encrypted.uchar(), enc_message.uchar(), public_rsa, RSA_PKCS1_OAEP_PADDING);
            free(public_rsa);
            
            if( enc_message.length > 0 )
            {
                return enc_message.base64();
            }
        }
        
        return "";
    }
    
    static std::string private_decrypt( const std::string & key, const std::string & passphrase, const std::string & data, const std::string & format )
    {
        RSA * private_rsa = excalibur_crypto_openssl::create_private_rsa(key.c_str(), passphrase.c_str());
        
        if( private_rsa != NULL )
        {
            crypto::buffer encrypted(data, crypto::BASE64);
            
            int rsa_len = RSA_size(private_rsa);
            crypto::buffer dec_message(rsa_len);
            
            dec_message.length = RSA_private_decrypt((int)encrypted.length, encrypted.uchar(), dec_message.uchar(), private_rsa, RSA_PKCS1_OAEP_PADDING);
            free(private_rsa);
            
            if( dec_message.length > 0 )
            {
                return dec_message.str(crypto::type(format));
            }
        }
        
        return "";
    }
    
    static std::string private_encrypt( const std::string & key, const std::string & passphrase, const std::string & data, const std::string & format )
    {
        RSA * private_rsa = excalibur_crypto_openssl::create_private_rsa(key.c_str(), passphrase.c_str());
        
        if( private_rsa != NULL )
        {
            crypto::buffer buff(data, crypto::type(format));
            crypto::buffer hash(SHA512_DIGEST_LENGTH);
            
            SHA512_CTX ctx;
            SHA512_Init(&ctx);
            SHA512_Update(&ctx, buff.data, buff.length);
            SHA512_Final(hash.data, &ctx);
            
            int rsa_len = RSA_size(private_rsa);
            crypto::buffer enc_message(rsa_len);
            
            enc_message.length = RSA_private_encrypt((int)SHA512_DIGEST_LENGTH, hash.uchar(), enc_message.uchar(), private_rsa, RSA_PKCS1_PADDING);
            free(private_rsa);
            
            if( enc_message.length > 0 )
            {
                return enc_message.base64();
            }
        }
        
        return "";
    }
    
    static std::string p12( const std::string & key, const std::string & cert, const std::string & passphrase )
    {
        BIO * certMem = BIO_new(BIO_s_mem());
        BIO_puts(certMem, cert.c_str());
        
        if( certMem == NULL )
        {
            printf( "ERROR: Could not load PUBLIC KEY! BIO_puts FAILED: %s\n", ERR_error_string( ERR_get_error(), NULL ) );
            BIO_free(certMem);
            
            return "";
        }
        
        X509 * certificate = PEM_read_bio_X509(certMem, NULL, NULL, NULL);
        BIO_free(certMem);
        
        if( certificate == NULL )
        {
            printf( "ERROR: Could not load PUBLIC KEY! PEM_read_bio_X509 FAILED: %s\n", ERR_error_string( ERR_get_error(), NULL ) );
            X509_free(certificate);
            
            return "";
        }
        
        BIO * keyMem = BIO_new(BIO_s_mem());
        BIO_puts(keyMem, key.c_str());
        
        if( keyMem == NULL )
        {
            printf( "ERROR: Could not load PRIVATE KEY! BIO_puts FAILED: %s\n", ERR_error_string( ERR_get_error(), NULL ) );
            BIO_free(keyMem);
            X509_free(certificate);
            
            return "";
        }
        
        EVP_PKEY * privateKey = PEM_read_bio_PrivateKey(keyMem, NULL, NULL, NULL);
        BIO_free(keyMem);
        
        if( privateKey == NULL )
        {
            printf( "ERROR: Could not load PRIVATE KEY! PEM_read_bio_PrivateKey FAILED: %s\n", ERR_error_string( ERR_get_error(), NULL ) );
            EVP_PKEY_free(privateKey);
            X509_free(certificate);
            
            return "";
        }
        
        if( X509_check_private_key(certificate, privateKey) != 1 )
        {
            return "";
        }
        
        PKCS12 * p12 = PKCS12_create(passphrase.c_str(), "Excalibur_pfx", privateKey, certificate, NULL, 0,0,0,0,0);
        
        if( !p12 )
        {
            fprintf(stderr, "Error creating PKCS#12");
            ERR_print_errors_fp(stderr);
            
            return "";
        }
        
        STACK_OF(X509) * ca = NULL;
        EVP_PKEY * parseKey;
        X509 * parseCert;
        
        if( !PKCS12_parse(p12, passphrase.c_str(), &parseKey, &parseCert, &ca) )
        {
            printf("error parsing PKCS#12 file");
            return "";
        }
        
        EVP_PKEY_free(parseKey);
        X509_free(parseCert);
        
        BIO * bio = BIO_new(BIO_s_mem());
        i2d_PKCS12_bio(bio, p12);
        
        if( bio == NULL )
        {
            fprintf(stderr, "Error creating PKCS#12");
            
            EVP_PKEY_free(privateKey);
            X509_free(certificate);
            PKCS12_free(p12);
            
            return "";
        }
        
        BUF_MEM * buffer;
        BIO_get_mem_ptr(bio, &buffer);
        
        std::string pfx = std::string(toBase64(buffer->data, (int)buffer->length));
        
        BIO_free_all(bio);
        EVP_PKEY_free(privateKey);
        X509_free(certificate);
        PKCS12_free(p12);
        
        return pfx;
    }
    
    static char * toBase64( char* str, int length )
    {
        BIO *bio, *b64;
        BUF_MEM *bufferPtr;
        
        b64 = BIO_new(BIO_f_base64());
        bio = BIO_new(BIO_s_mem());
        bio = BIO_push(b64, bio);
        
        BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
        BIO_write(bio, str, length);
        BIO_flush(bio);
        BIO_get_mem_ptr(bio, &bufferPtr);
        BIO_set_close(bio, BIO_NOCLOSE);
        BIO_free_all(bio);
        char * output;
        
        output = (*bufferPtr).data;
        return output;
    }
    
  private:
    
    static int aes_gcm_encrypt( unsigned char *plaintext, int plaintext_len, unsigned char *aad, int aad_len, unsigned char *key, unsigned char *iv, int iv_len, unsigned char *ciphertext, unsigned char *tag )
    {
        EVP_CIPHER_CTX *ctx;
        int len;
        int ciphertext_len;
        
        if( !( ctx = EVP_CIPHER_CTX_new() ) ){ return -1; }
        if( 1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) ){ return -1; }
        if( 1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL) ){ return -1; }
        if( 1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) ){ return -1; }
        if( 1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len) ){ return -1; }
        if( 1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) ){ return -1; }
        ciphertext_len = len;
        
        if( 1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) ){ return -1; }
        ciphertext_len += len;
        
        if( 1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) ){ return -1; }
        
        EVP_CIPHER_CTX_free(ctx);
        
        return ciphertext_len;
    }
    
    static int aes_gcm_decrypt( unsigned char *ciphertext, int ciphertext_len, unsigned char *aad, int aad_len, unsigned char *tag, unsigned char *key, unsigned char *iv, int iv_len, unsigned char * plaintext )
    {
        EVP_CIPHER_CTX *ctx;
        int len;
        int plaintext_len;
        int ret;
        
        if( !( ctx = EVP_CIPHER_CTX_new() ) ){ return -1; }
        if( !EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) ){ return -1; }
        if( !EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL) ){ return -1; }
        if( !EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) ){ return -1; }
        if( !EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len) ){ return -1; }
        if( !EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len) ){ return -1; }
        plaintext_len = len;
        
        if( !EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag) ){ return -1; }
        
        ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
        
        EVP_CIPHER_CTX_free(ctx);
        
        if( ret > 0 )
        {
            plaintext_len += len;
            return plaintext_len;
        }
        else
        {
            return -1;
        }
    }
    
    static RSA * create_public_rsa( const char * cert )
    {
        X509 * rsa_cert;
        BIO * mem;
        
        mem = BIO_new(BIO_s_mem());
        BIO_puts(mem, cert);
        
        if( mem == NULL )
        {
            printf( "ERROR: Could not load PUBLIC KEY! BIO_puts FAILED: %s\n", ERR_error_string( ERR_get_error(), NULL ) );
            
            return 0;
        }
        
        rsa_cert = PEM_read_bio_X509(mem, NULL, NULL, NULL);
        BIO_free(mem);
        
        if( rsa_cert == NULL )
        {
            printf( "ERROR: Could not load PUBLIC KEY! PEM_read_bio_X509 FAILED: %s\n", ERR_error_string( ERR_get_error(), NULL ) );
            
            return 0;
        }
        
        EVP_PKEY * pub_key;
        RSA * rsa = NULL;
        
        pub_key = X509_get_pubkey(rsa_cert);
        
        if( pub_key == NULL )
        {
            printf( "ERROR: Could not load PUBLIC KEY! X509_get_pubkey FAILED: %s\n", ERR_error_string( ERR_get_error(), NULL ) );
            
            return 0;
        }
        
        rsa = EVP_PKEY_get1_RSA(pub_key);
        
        EVP_PKEY_free(pub_key);
        
        return rsa;
    }
    
    static RSA * create_private_rsa( const char * key, const char * passphrase )
    {
        RSA * rsa = nullptr;
        
        BIO * privKeyBio = BIO_new_mem_buf(key, -1);
        if( privKeyBio )
        {
            if( !std::string(passphrase).empty() )
            {
                PEM_read_bio_RSAPrivateKey(privKeyBio, &rsa, excalibur_crypto_openssl::password_callback, (void*)&passphrase);
            }
            else
            {
                PEM_read_bio_RSAPrivateKey(privKeyBio, &rsa, NULL, NULL);
            }
            
            BIO_free(privKeyBio);
        }
        
        return rsa;
    }
    
    static bool rsa_sign( RSA * rsa, const unsigned char * msg, size_t msg_len, unsigned char ** enc_msg, size_t* msg_len_enc )
    {
        EVP_MD_CTX * m_rsa_sign_ctx = EVP_MD_CTX_create();
        EVP_PKEY * pri_key = EVP_PKEY_new();
        EVP_PKEY_assign_RSA(pri_key, rsa);
        
        if( EVP_DigestSignInit(m_rsa_sign_ctx, NULL, EVP_sha512(), NULL, pri_key) <= 0 ){ return false; }
        if( EVP_DigestSignUpdate(m_rsa_sign_ctx, msg, msg_len) <= 0 ){ return false; }
        if( EVP_DigestSignFinal(m_rsa_sign_ctx, NULL, msg_len_enc) <= 0 ){ return false; }
        
        *enc_msg = (unsigned char *)malloc(*msg_len_enc);
        if( EVP_DigestSignFinal(m_rsa_sign_ctx, *enc_msg, msg_len_enc) <= 0 ){ return false; }
        
        EVP_MD_CTX_free(m_rsa_sign_ctx);
        return true;
    }
    
    static int password_callback(char *buf, int/* size*/, int/* rwflag*/, void *u)
    {
        auto pass = (std::string*)u;
        auto ii = pass->length();
        
        for (decltype(ii) i = 0; i < ii; ++i) { buf[i] = (*pass)[i]; }
        
        return (int)pass->length();
    }
    
  public:
    
    static const uint8_t iv_static[12];
};

namespace CSR
{
    class rsa;
    
    typedef std::shared_ptr<rsa> rsa_ptr;
    
    class rsa
    {
      public:
        static rsa_ptr generate( int bits )
        {
            rsa_ptr r;
            
            BIGNUM *bn = BN_new();
            if( bn )
            {
                int ret = BN_set_word(bn, RSA_F4);
                if( ret == 1 )
                {
                    RSA * pRsa = RSA_new();
                    
                    if( pRsa )
                    {
                        ret = RSA_generate_key_ex(pRsa, bits, bn, nullptr);
                        
                        if( ret == 1 )
                        {
                            r = std::shared_ptr<CSR::rsa>(new CSR::rsa(pRsa));
                        }
                        else
                        {
                            RSA_free(pRsa);
                        }
                    }
                }
                
                BN_free(bn);
            }
            
            return r;
        }
        
        ~rsa()
        {
            RSA_free(m_privateRsa);
        }
        
        explicit operator RSA*()
        {
            RSA_up_ref(m_privateRsa);
            
            return m_privateRsa;
        }
        
      private:
        rsa(RSA* pRsa)
        : m_privateRsa(pRsa)
        {
        }
        
        // TODO: separate RSAs for public & private key crypto!
        RSA* m_privateRsa;
        RSA* m_publicRsa;
    };
    
    static std::string getPrivate( rsa_ptr rsa )
    {
        RSA * pRsa = (RSA*)*rsa.get();
        BIO * bio = BIO_new(BIO_s_mem());
        PEM_write_bio_RSAPrivateKey(bio, pRsa, NULL, NULL, 0, NULL, NULL);
        
        BUF_MEM * bufferPtr;
        BIO_get_mem_ptr(bio, &bufferPtr);
        
        crypto::buffer buffer(std::string(bufferPtr->data, bufferPtr->length), crypto::STRING);
        buffer.length = bufferPtr->length;
        std::string privateCrt = buffer.string();
        
        BIO_free(bio);
        
        return privateCrt;
    }
    
    static std::string generate_csr(CSR::rsa_ptr rsa, const std::string & company_id, const std::string & device_id, const std::string & type)
    {
        std::string r;
        
        X509_REQ * x509Req = X509_REQ_new();
        if (x509Req) {
            int ret = X509_REQ_set_version(x509Req, 1);
            X509_NAME * x509Name = X509_REQ_get_subject_name(x509Req);
            if (x509Name) {
                ret = X509_NAME_add_entry_by_txt(x509Name, "C", MBSTRING_ASC, (const unsigned char*)"SK", -1, -1, 0);
                if (ret == 1) {
                    ret = X509_NAME_add_entry_by_txt(x509Name, "O", MBSTRING_ASC, (const unsigned char*)"Excalibur s.r.o.", -1, -1, 0);
                }
                
                if (ret == 1) {
                    ret = X509_NAME_add_entry_by_txt(x509Name, "L", MBSTRING_ASC, (const unsigned char*)company_id.c_str(), -1, -1, 0);
                }
                
                if (ret == 1) {
                    ret = X509_NAME_add_entry_by_txt(x509Name, "OU", MBSTRING_ASC, (const unsigned char*)type.c_str(), -1, -1, 0);
                }
                
                if (ret == 1) {
                    ret = X509_NAME_add_entry_by_txt(x509Name, "CN", MBSTRING_ASC, (const unsigned char*)device_id.c_str(), -1, -1, 0);
                }
                
                if (ret == 1) {
                    EVP_PKEY *pkey = EVP_PKEY_new();
                    if (pkey) {
                        RSA* pRsa = (RSA*)*rsa.get();
                        ret = EVP_PKEY_assign_RSA(pkey, pRsa);
                        if (ret == 1) {
                            ret = X509_REQ_set_pubkey(x509Req, pkey);
                            if (ret == 1) {
                                ret = X509_REQ_sign(x509Req, pkey, EVP_sha256());
                                if (ret > 0) { // sign returns size of signature!
                                    BIO * bio = BIO_new(BIO_s_mem());
                                    if (bio) {
                                        ret = PEM_write_bio_X509_REQ(bio, x509Req);
                                        if (ret == 1) {
                                            BUF_MEM * buff;
                                            BIO_get_mem_ptr(bio, &buff);
                                            
                                            r = std::string(buff->data, buff->length);
                                        }
                                        
                                        BIO_free(bio);
                                    }
                                    
                                }
                            }
                        }
                        
                        EVP_PKEY_free(pkey);
                    }
                }
            }
            
            X509_REQ_free(x509Req);
        }
        
        return r;
    }
}

const uint8_t excalibur_crypto_openssl::iv_static[12] = { 0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88 };
