/* Created by Keltika.
 * Copyright (c) 2018 Excalibur (exc sp. z.o.o.). All rights reserved.
 * NOTICE:  All information contained herein is, and remains
 * the property of exc sp. z.o.o. and its suppliers,
 * if any.  The intellectual and technical concepts contained
 * herein are proprietary to exc sp. z.o.o.
 * and its suppliers and may be covered by U.S. and Foreign Patents,
 * patents in process, and are protected by trade secret or copyright law.
 * Dissemination of this information or reproduction of this material
 * is strictly forbidden unless prior written permission is obtained
 * from exc sp. z.o.o.
 */
#include "excalibur_crypto.cpp"
#include <jni.h>

#define FUNCTION(name) Java_com_xclbr_crypto_RNExcaliburCryptoModule_ ## name

std::string jstring2string(JNIEnv *env, jstring jStr) {
    if (!jStr)
        return "";

    const jclass stringClass = env->GetObjectClass(jStr);
    const jmethodID getBytes = env->GetMethodID(stringClass, "getBytes", "(Ljava/lang/String;)[B");
    const jbyteArray stringJbytes = (jbyteArray) env->CallObjectMethod(jStr, getBytes, env->NewStringUTF("UTF-8"));

    size_t length = (size_t) env->GetArrayLength(stringJbytes);
    jbyte* pBytes = env->GetByteArrayElements(stringJbytes, NULL);

    std::string ret = std::string((char *)pBytes, length);
    env->ReleaseByteArrayElements(stringJbytes, pBytes, JNI_ABORT);

    env->DeleteLocalRef(stringJbytes);
    env->DeleteLocalRef(stringClass);
    return ret;
}

extern "C" {

    jstring FUNCTION(privateDecrypt)(JNIEnv *env, jobject obj, jstring j_key, jstring j_passphrase, jstring j_data, jstring j_format) {
        std::string key = jstring2string(env, j_key);
        std::string passphrase = jstring2string(env, j_passphrase);
        std::string data = jstring2string(env, j_data);
        std::string format = jstring2string(env, j_format);

        std::string retval = excalibur_crypto_openssl::private_decrypt(key, passphrase, data, format);
        return env->NewStringUTF(retval.c_str());
    }

    jstring FUNCTION(aesGcmEncrypt)(JNIEnv *env, jobject obj, jstring j_key, jstring j_data, jstring j_auth, jstring j_iv) {
        std::string key = jstring2string(env, j_key);
        std::string data = jstring2string(env, j_data);
        std::string auth = jstring2string(env, j_auth);
        std::string iv = jstring2string(env, j_iv);

        std::string retval = excalibur_crypto_openssl::aes_gcm_encrypt(key, data, auth, iv);
        return env->NewStringUTF(retval.c_str());
    }

    jstring FUNCTION(aesGcmDecrypt)(JNIEnv *env, jobject obj, jstring j_key, jstring j_data, jstring j_auth, jstring j_iv) {
        std::string key = jstring2string(env, j_key);
        std::string data = jstring2string(env, j_data);
        std::string auth = jstring2string(env, j_auth);
        std::string iv = jstring2string(env, j_iv);

        std::string retval = excalibur_crypto_openssl::aes_gcm_decrypt(key, data, auth, iv);
        return env->NewStringUTF(retval.c_str());
    }

    jstring FUNCTION(privateEncrypt)(JNIEnv *env, jobject obj, jstring j_key, jstring j_passphrase, jstring j_data, jstring j_format) {
        std::string key = jstring2string(env, j_key);
        std::string passphrase = jstring2string(env, j_passphrase);
        std::string data = jstring2string(env, j_data);
        std::string format = jstring2string(env, j_format);

        std::string retval = excalibur_crypto_openssl::private_encrypt(key, passphrase, data, format);
        return env->NewStringUTF(retval.c_str());
    }

    jstring FUNCTION(publicEncrypt)(JNIEnv *env, jobject obj, jstring j_cert, jstring j_data, jstring j_format) {
        std::string cert = jstring2string(env, j_cert);
        std::string data = jstring2string(env, j_data);
        std::string format = jstring2string(env, j_format);

        std::string retval = excalibur_crypto_openssl::public_encrypt(cert, data, format);
        return env->NewStringUTF(retval.c_str());
    }

    jstring FUNCTION(sha256)(JNIEnv *env, jobject obj, jstring j_data) {
        std::string data = jstring2string(env, j_data);

        std::string retval = crypto::sha256(data);
        return env->NewStringUTF(retval.c_str());
    }

    jstring FUNCTION(sha512)(JNIEnv *env, jobject obj, jstring j_data) {
        std::string data = jstring2string(env, j_data);

        std::string retval = crypto::sha512(data);
        return env->NewStringUTF(retval.c_str());
    }

    jstring FUNCTION(p12)(JNIEnv *env, jobject obj, jstring j_key, jstring j_cert, jstring j_passphrase) {
        std::string key = jstring2string(env, j_key);
        std::string cert = jstring2string(env, j_cert);
        std::string passphrase = jstring2string(env, j_passphrase);

        std::string retval = excalibur_crypto_openssl::p12(key, cert, passphrase);
        return env->NewStringUTF(retval.c_str());
    }

    jstring FUNCTION(pbkdf2)(JNIEnv *env, jobject obj, jstring j_pass, jstring j_salt, int iterations) {
        std::string pass = jstring2string(env, j_pass);
        std::string salt = jstring2string(env, j_salt);

        std::string retval = crypto::pbkdf2(pass, salt, iterations);
        return env->NewStringUTF(retval.c_str());
    }

    jstring FUNCTION(hexToBase64)(JNIEnv *env, jobject obj, jstring j_data) {
        std::string data = jstring2string(env, j_data);

        crypto::buffer hex(data, crypto::HEX);
        std::string retval = hex.base64();
        return env->NewStringUTF(retval.c_str());
    }

    jobjectArray FUNCTION(generateCSR)( JNIEnv *env, jobject obj, jstring j_company_id, jstring j_device_id, jstring j_device_type )
    {
        std::string company_id = jstring2string(env, j_company_id);
        std::string device_id = jstring2string(env, j_device_id);
        std::string device_type = jstring2string(env, j_device_type);

        auto rsa = CSR::rsa::generate(2048);
        auto csr = CSR::generate_csr(rsa, company_id, device_id, device_type);
        if( !csr.empty() )
        {
            auto privateKey = CSR::getPrivate(rsa);
            if( !privateKey.empty() )
            {
                jobjectArray retobjarr = (jobjectArray)env->NewObjectArray(2, env->FindClass("java/lang/Object"), NULL);
                env->SetObjectArrayElement(retobjarr, 0, env->NewStringUTF(privateKey.c_str()));
                env->SetObjectArrayElement(retobjarr, 1, env->NewStringUTF(csr.c_str()));

                return retobjarr;
            }
        }

        jobjectArray retobjarr = (jobjectArray)env->NewObjectArray(0, env->FindClass("java/lang/Object"), NULL);
        return retobjarr;
    }
}