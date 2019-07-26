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
package com.xclbr.crypto;

import android.annotation.SuppressLint;
import android.content.Context;
import android.content.SharedPreferences;
import android.hardware.fingerprint.FingerprintManager;
import android.os.Build;
import android.os.CancellationSignal;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import android.util.Log;

import com.facebook.react.bridge.Promise;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.bridge.ReadableArray;
import com.facebook.react.bridge.ReadableMap;
import com.facebook.react.bridge.WritableMap;
import com.facebook.react.bridge.WritableNativeMap;
import com.facebook.react.modules.core.DeviceEventManagerModule;
import com.google.firebase.iid.FirebaseInstanceId;
import com.xclbr.keychain.RNExcaliburKeychainModule;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.Charset;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyManagementException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

public class RNExcaliburCryptoModule extends ReactContextBaseJavaModule {
	public static final String TAG = "EX:CryptoModule";

	private static final boolean D = BuildConfig.DEBUG;
	private static final int KEYSTORE_AUTHENTICATION_VALIDITY = 3600 * 24;
	private static final boolean KEYSTORE_API_AVAILABLE = (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M);

	private static final String SIGNATURE_ALG = "SHA256withRSA";
	private static final String ALGORITHM = "RSA-SHA256";

	private static final String E_GENERATE_CERT = "generate_cert_error";
	private static final String E_SIGN_FACTOR = "sign_factor_error";
	private static final String E_KEYS = "crypto_keys_error";
	private static final String E_AUTH = "auth_error";
	private static final String E_VERIFY = "verify_error";
	private static final String E_REMOVE = "remove_error";
	private static final String E_JSON = "json_error";

	private static final String E_BAD_CERTIFICATE = "bad_certificate";
	private static final String E_UNKNOWN_USER = "unknown_user";
	private static final String E_BAD_PIN = "bad_pin";

	private static final String EMITTER_EVENT_FACTOR_STATUS = "factorStatus";

	private static final String S_GENERATING = "generating";
	private static final String S_INITIALIZED = "initialized";
	private static final String S_FAILED = "failed";
	private static final String S_AUTH_FAILED = "auth_failed";
	private static final String S_OS_ERROR = "os_error";
	private static final String S_OS_HELP = "os_help";

	private static CancellationSignal cancellationSignal = null;

	static {
		System.loadLibrary("excalibur-crypto");
	}

	private static ExecutorService s_executor = Executors.newFixedThreadPool(10);
	private static ExecutorService s_fetch_executor = Executors.newFixedThreadPool(10);

	private SharedPreferences certificatesStorage;
	private final ReactApplicationContext reactContext;
	private KeyStore keyStore = null;
	private static final Object keyStoreLock = new Object();

	public RNExcaliburCryptoModule(ReactApplicationContext reactContext)
	{
		super( reactContext );
		this.reactContext = reactContext;
		this.certificatesStorage = reactContext.getSharedPreferences("excalibur-crypto-certificates-storage", Context.MODE_PRIVATE);
	}

	@Override
	public String getName()
	{
		return "RNExcaliburCrypto";
	}

	//region REACT METHODS
	@ReactMethod
	public void migrate(final Promise promise)
	{
		s_executor.submit(new Runnable() {
			@Override
			public void run() {
				for(Map.Entry<String, ?> entry : certificatesStorage.getAll().entrySet()){
					RNExcaliburKeychainModule.saveString(reactContext, entry.getKey(), (String) entry.getValue());
					certificatesStorage.edit().remove(entry.getKey()).apply();
				}
				promise.resolve(true);
			}
		});
	}

	@ReactMethod
    public void removeFactorsCertificates(final ReadableArray factors, final Promise promise)
	{
		s_executor.submit(new Runnable() {
			@Override
			public void run(){

				for( int i = 0; i < factors.size(); i++ )
				{
					String factor = factors.getString(i);

					if( hasGeneratedKeys(factor) ) {
						if( KEYSTORE_API_AVAILABLE ) {

							try {
								getKeyStore().deleteEntry( factorAlias(factor) );
							} catch (KeyStoreException | CertificateException | NoSuchAlgorithmException | IOException e) {
								if( D ) Log.e( TAG, "Removing keystore certificate for factor "+factor+" failed! ", e);
							}

						} else {

							boolean removed =
									RNExcaliburKeychainModule.remove(reactContext, factorAlias(factor) + ".private" ) &&
                                    RNExcaliburKeychainModule.remove(reactContext, factorAlias(factor) + ".public" );

							if( !removed ){
								if( D ) Log.e( TAG, "Removing keychain certificate for factor " + factor + " failed!");
							}
						}
					}
				}

				promise.resolve(true);
			}
		});
	}

	@ReactMethod
	public void generateFactorCertificate( final String factor, final Promise promise )
	{
		s_executor.submit(new Runnable() {
			@Override
			public void run() {
				try {

					generateFactorCertificate( factor );
					promise.resolve( true );

				} catch (NoSuchProviderException | NoSuchAlgorithmException
						| InvalidAlgorithmParameterException | InvalidKeyException | BadPaddingException
						| NoSuchPaddingException | IllegalBlockSizeException | IOException e) {

					promise.reject( e );
				}
			}
		});
	}

	@ReactMethod
	public void fetch(final String url, final String data, final ReadableMap options, final Promise promise)
	{
		s_fetch_executor.submit(new Runnable() {
			@Override
			public void run() {

				ReadableMap certs = options != null && options.hasKey("company-id") ?
						getCompanyCertificates( options.getString("company-id") ) : options;

				fetchRequest(url, data, certs, new FetchCallbacks() {
					@Override
					public void onSuccess(String results) {
						if( D ) Log.d(TAG, "fetch("+url+", "+data+") success with results="+results);
						promise.resolve(results);
					}

					@Override
					public void onError(Exception e) {
						if( D ) Log.d(TAG, "fetch("+url+", "+data+") failed with error="+e.toString());
						promise.reject(e);
					}
				});
			}
		});
	}

	@ReactMethod
	public void setUserCertificate(final String companyID, final String name, final String cert, final String key, final String pass, final Promise promise)
	{
		s_executor.submit(new Runnable() {
			@Override
			public void run() {

				String passphrase = ( pass.isEmpty()) ? "" : sha512(pass).substring(0, 80);

				// TODO: navratovu hodnotu treba osetrit
				RNExcaliburKeychainModule.saveString(reactContext,companyID + "/certificates/user-" + name + ".crt", cert);
				RNExcaliburKeychainModule.saveString(reactContext,companyID + "/certificates/user-" + name + ".key", key);
				RNExcaliburKeychainModule.saveString(reactContext,companyID + "/certificates/user-" + name + ".pass", passphrase);

				promise.resolve(true);
			}
		});
	}

	@ReactMethod
	public void getUserCertificate(final String companyID, final String name, final Promise promise)
	{
		s_executor.submit(new Runnable() {
			@Override
			public void run() {
				String cert = RNExcaliburKeychainModule.loadString(reactContext,companyID + "/certificates/user-" + name + ".crt");

				if(!cert.isEmpty())
					promise.resolve( cert );
				else
					promise.reject(E_UNKNOWN_USER, "");
			}
		});
	}

	@ReactMethod
	public void getUserCertificateHash(final String companyID, final String name, final Promise promise)
	{
		s_executor.submit(new Runnable() {
			@Override
			public void run() {
				String cert = RNExcaliburKeychainModule.loadString(reactContext,companyID + "/certificates/user-" + name + ".crt");

				if(!cert.isEmpty()) { promise.resolve(hexToBase64(sha256(cert))); }
				else { promise.reject(E_UNKNOWN_USER, ""); }
			}
		});
	}

	@ReactMethod
	public void signWithUserCertificate(final String companyID, final String name, final String data, final String format, final Promise promise)
	{
		s_executor.submit(new Runnable() {
			@Override
			public void run() {
				String cert = RNExcaliburKeychainModule.loadString(reactContext,companyID + "/certificates/user-" + name + ".crt");
				String key = RNExcaliburKeychainModule.loadString(reactContext,companyID + "/certificates/user-" + name + ".key");
				String pass = RNExcaliburKeychainModule.loadString(reactContext,companyID + "/certificates/user-" + name + ".pass");

				if( !key.isEmpty() && !pass.isEmpty() )
				{
					String privateSign = privateEncrypt(key, pass, data, format);

					if(!privateSign.isEmpty())
						promise.resolve(privateSign);
					else
						promise.reject(E_BAD_CERTIFICATE, "PrivateEncrypt failed!");
				}
				else if( !cert.isEmpty() )
				{
					String publicSign = publicEncrypt(cert, data, format);

					if(!publicSign.isEmpty())
						promise.resolve(publicSign);
					else
						promise.reject(E_BAD_CERTIFICATE, "PublicEncrypt failed!");
				}
				else
				{
					promise.reject(E_UNKNOWN_USER, "");
				}
			}
		});
	}

	@ReactMethod
	public void privateDecryptWithUserCertificate(final String companyID, final String name, final String data, final String format, final Promise promise)
	{
		s_executor.submit(new Runnable() {
			@Override
			public void run() {
				String key = RNExcaliburKeychainModule.loadString(reactContext,companyID + "/certificates/user-" + name + ".key");
				String pass = RNExcaliburKeychainModule.loadString(reactContext,companyID + "/certificates/user-" + name + ".pass");

				if( !key.isEmpty() && !pass.isEmpty() )
				{
					String sign = privateDecrypt(key, pass, data, format);

					if(!sign.isEmpty()) { promise.resolve(sign); }
					else { promise.reject(E_BAD_CERTIFICATE, "PrivateDecrypt failed!"); }
				}
				else
				{
					promise.reject(E_UNKNOWN_USER, "");
				}
			}
		});
	}

	@ReactMethod
	public void verifyWithUserCertificate(String companyID, String name, String data, String format, final Promise promise)
	{
		s_executor.submit(new Runnable() {
			@Override
			public void run() {
				try {
					JSONObject retval = new JSONObject();
					retval.put("ok", true);

					promise.resolve(retval);
				} catch (JSONException e) {
					promise.reject(E_VERIFY, e);
				}
			}
		});
	}

	@ReactMethod
	public void getFactorPublicKey( final String factor, final String intent, final String text, final String data, final Promise promise )
	{
		s_executor.submit(new Runnable()
		{
			@Override
			public void run()
			{
				String dataToSign = data;

				if( factor.equals("pin") )
				{
					try
					{
						JSONObject intentJson = new JSONObject(intent);
						String userID = intentJson.getString("userID");
						String uniqueID = FirebaseInstanceId.getInstance().getId();

						String uniqueIDHash = pbkdf2(data, uniqueID, 10000);
						String userIDHash = pbkdf2(data, userID, 10000);

						RNExcaliburKeychainModule.saveString(reactContext,factor + ".hash", uniqueIDHash);

						dataToSign = String.format("{\"hash\":\"%s\"}", userIDHash);
					}
					catch( JSONException e ) { promise.reject(E_JSON, e); return; }
				}

				if( !hasGeneratedKeys(factor) )
				{
					try
					{
						emitFactorStatus(factor, S_GENERATING, "");

						generateFactorCertificate(factor);
					}
					catch( NoSuchProviderException | NoSuchAlgorithmException | InvalidAlgorithmParameterException |
							RuntimeException | IOException | NoSuchPaddingException | InvalidKeyException |
							IllegalBlockSizeException | BadPaddingException e )
					{
						promise.reject(E_GENERATE_CERT, e);
						return;
					}
				}

				final FactorKeyPair factorKeys = new FactorKeyPair();
				try
				{
					loadFactorKeys(factor, factorKeys);
				}
				catch( CertificateException | NoSuchAlgorithmException | KeyStoreException | IOException |
						UnrecoverableKeyException | NoSuchPaddingException | InvalidKeyException |
						IllegalBlockSizeException | BadPaddingException | InvalidKeySpecException e )
				{
					promise.reject(E_KEYS, e);
					return;
				}

				final String signedData = dataToSign;

				cancellationSignal = new CancellationSignal();
				signFactorData( factor, factorKeys, intent, signedData, cancellationSignal, new SigningCallbacks()
				{
					@Override
					public void onInitialized()
					{
						emitFactorStatus(factor, S_INITIALIZED, "");
					}

					@Override
					public void onSigned( String signature, String dataSignature )
					{
						WritableMap map = new WritableNativeMap();
						map.putString("algorithm", ALGORITHM);
						map.putString("public-key", convertToPem(factorKeys.getPublicKey()));
						map.putString("signature", signature);

						cancellationSignal = null;

						if( !signedData.isEmpty() )
						{
							try
							{
								JSONObject dataJson = new JSONObject(signedData);

								dataJson.put("signature", dataSignature);
								map.putString(factor, dataJson.toString());
							}
							catch( JSONException e ) { promise.reject(E_JSON, e); return; }
						}

						promise.resolve(map);
					}

					@Override
					public void onSignError( Exception e )
					{
						if( D ) Log.e(TAG, "Signing error: exception="+e.toString());

						/* Not working
						if( e instanceof InvalidKeyException ) {
							try {
								getKeyStore().deleteEntry(factorAlias(factor));
							} catch (KeyStoreException | CertificateException | NoSuchAlgorithmException | IOException e1) {
								e1.printStackTrace();
							}
						}
						*/

						cancellationSignal = null;
						promise.reject(E_SIGN_FACTOR, e);
					}

					@Override
					public void onAuthenticationFailed()
					{
						if( D ) Log.e(TAG, "Authentication failed!");
						emitFactorStatus(factor, S_AUTH_FAILED, "");
					}

					@Override
					public void onAuthenticationError( int errorCode, String errString )
					{
						if( D ) Log.e(TAG, "Authentication error: code="+errString+" str="+errString);
						cancellationSignal = null;
						emitFactorStatus(factor, S_OS_ERROR, errString);
						promise.reject(E_AUTH, errString);
					}

					@Override
					public void onAuthenticationHelp(int helpCode, String helpString)
					{
						if( D ) Log.e(TAG, "Authentication help: code="+helpCode+" str="+helpString);
						emitFactorStatus(factor, S_OS_HELP, helpString);
					}
				});
			}
		});
	}

	@ReactMethod
	public void signWithFactor( final String factor, final String intent, final String text, final String data, final Promise promise )
	{
		s_executor.submit(new Runnable()
		{
			@Override
			public void run()
			{
				String dataToSign = data;

				if( factor.equals("pin") )
				{
					try
					{
						JSONObject intentJson = new JSONObject(intent);
						String userID = intentJson.getString("userID");
						String uniqueID = FirebaseInstanceId.getInstance().getId();

						String uniqueIDHash = pbkdf2(data, uniqueID, 10000);
						String userIDHash = pbkdf2(data, userID, 10000);
						String savedHash = RNExcaliburKeychainModule.loadString(reactContext,factor + ".hash");

						if( !uniqueIDHash.equals(savedHash) )
						{
							promise.reject(E_BAD_PIN, "");
							return;
						}

						dataToSign = String.format("{\"hash\":\"%s\"}", userIDHash);
					}
					catch( JSONException e ) { promise.reject(E_JSON, e); return; }
				}

				final FactorKeyPair factorKeys = new FactorKeyPair();
				try
				{
					loadFactorKeys(factor, factorKeys);
				}
				catch( CertificateException | NoSuchAlgorithmException | KeyStoreException | IOException |
						UnrecoverableKeyException | NoSuchPaddingException | InvalidKeyException |
						IllegalBlockSizeException | BadPaddingException | InvalidKeySpecException e )
				{
					promise.reject(E_KEYS, e);
					return;
				}

				final String signedData = dataToSign;

				cancellationSignal = new CancellationSignal();
				signFactorData( factor, factorKeys, intent, signedData, cancellationSignal, new SigningCallbacks()
				{
					@Override
					public void onInitialized() {
							emitFactorStatus(factor, S_INITIALIZED, "");
					}

					@Override
					public void onSigned( String signature, String dataSignature )
					{
						WritableMap map = new WritableNativeMap();
						map.putString("signature", signature);

						cancellationSignal = null;

						if( !signedData.isEmpty() )
						{
							try
							{
								JSONObject dataJson = new JSONObject(signedData);

								dataJson.put("signature", dataSignature);
								map.putString(factor, dataJson.toString());
							}
							catch( JSONException e ) { promise.reject(E_JSON, e); return; }
						}

						promise.resolve(map);
					}

					@Override
					public void onSignError( Exception e )
					{
						if( D ) Log.e(TAG, "Signing error: exception="+e.toString());

						/* not woking
						if( e instanceof InvalidKeyException ) {
							try {
								getKeyStore().deleteEntry(factorAlias(factor));
							} catch (KeyStoreException | CertificateException | NoSuchAlgorithmException | IOException e1) {
								e1.printStackTrace();
							}
						}
						*/

						cancellationSignal = null;
						promise.reject(E_SIGN_FACTOR, e);
					}

					@Override
					public void onAuthenticationFailed()
					{
						if( D ) Log.e(TAG, "Authentication failed");
						emitFactorStatus(factor, S_AUTH_FAILED, "");
					}

					@Override
					public void onAuthenticationError( int errorCode, String errString )
					{
						if( D ) Log.e(TAG, "Authentication error: code="+errorCode+" str="+errString);
						cancellationSignal = null;
						emitFactorStatus(factor, S_OS_ERROR, errString);
						promise.reject(E_AUTH, errString);
					}

					@Override
					public void onAuthenticationHelp( int helpCode, String helpString )
					{
						if( D ) Log.e(TAG, "Authentication help: code="+helpCode+" str="+helpString);
						emitFactorStatus(factor, S_OS_HELP, helpString);
					}
				});
			}
		});
	}

	@ReactMethod
	public void isFactorInitialized(final String factor, final Promise promise)
	{
		s_executor.submit(new Runnable() {
			@Override
			public void run() {
				boolean available = true;
				boolean initialized = false;

				switch(factor){
//					case "fingerprint" :
// 						available = isFingerprintAvailableAndEnrolled();
//						initialized = hasGeneratedKeys(factor);
// 						break;

					case "pin" :
						initialized = hasFactorHash(factor) && hasGeneratedKeys(factor);
						break;

					case "face" :
						available = false;
						initialized = hasGeneratedKeys(factor);
						break;

					default:
						initialized = hasGeneratedKeys(factor);
						break;
				}

				WritableMap map = new WritableNativeMap();
				map.putBoolean("initialized", initialized);
				map.putBoolean("available", available);

				promise.resolve(map);
			}
		});
	}

	@ReactMethod
	public void isPinFactorCorrect( final String pin, final Promise promise )
	{
		s_executor.submit(new Runnable()
		{
			@Override
			public void run()
			{
				String uniqueID = FirebaseInstanceId.getInstance().getId();

				String uniqueIDHash = pbkdf2(pin, uniqueID, 10000);
				String savedHash = RNExcaliburKeychainModule.loadString(reactContext,"pin.hash");

				promise.resolve(uniqueIDHash.equals(savedHash));
			}
		});
	}

	@ReactMethod
	public void cancelFactor(final String factor, final Promise promise)
	{
		s_executor.submit(new Runnable() {
			@Override
			public void run() {
				switch (factor){
					case "fingerprint" :
						if(cancellationSignal!=null && !cancellationSignal.isCanceled())
							cancellationSignal.cancel();
						break;

					default: break;
				}

				promise.resolve(true);
			}
		});
	}

	@ReactMethod
	public void getCompanyCertificates(final String companyID, final Promise promise)
	{
		s_executor.submit(new Runnable() {
			@Override
			public void run() {
				promise.resolve( getCompanyCertificates( companyID ) );
			}
		});
	}

	@ReactMethod
	public void setCompanyCertificates(final String companyID, final ReadableMap certificates, final Promise promise)
	{
		s_executor.submit(new Runnable() {
			@Override
			public void run() {

				if( certificates == null )
				{
					RNExcaliburKeychainModule.remove(reactContext, companyID + "/certificates.json");

					WritableMap res = new WritableNativeMap();
					res.putBoolean("ok", true);

					promise.resolve( res );
					return;
				}
				else if( certificates.isNull("server") || certificates.isNull("key") ||
						certificates.isNull("cert") || certificates.isNull("passphrase") )
				{
					promise.reject("error", "bad_arguments");
					return;
				}

				String passphrase = sha512( certificates.getString("passphrase") ).substring(0, 80);
				String pfx = p12( certificates.getString("key"), certificates.getString("cert"), passphrase );
				pfx = pfx.replace("\n", "");

				JSONObject certs_dict = new JSONObject();
				try
				{
					certs_dict.put("server", certificates.getString("server"));
					certs_dict.put("pfx", pfx);
					certs_dict.put("passphrase", passphrase);

					String certs_json = certs_dict.toString();

					RNExcaliburKeychainModule.saveString(reactContext,companyID + "/certificates.json", certs_json);
				}
				catch (JSONException e)
				{
					promise.reject("error", "not_saved");
					return;
				}

				WritableMap res = new WritableNativeMap();
				res.putBoolean("ok", true);

				promise.resolve( res );
			}
		});
	}

	@ReactMethod
	public void publicEncrypt(final String publicKey, final String data, final String format, final Promise promise)
	{
		s_executor.submit(new Runnable() {
			@Override
			public void run() {
				String encrypt = publicEncrypt(publicKey, data, format);

				if( !encrypt.isEmpty() ) { promise.resolve(encrypt); }
				else { promise.reject(E_BAD_CERTIFICATE, "Encrypt failed!"); }
			}
		});
	}

	@ReactMethod
	public void aesEncrypt(final String key, final String data, final String auth, final String iv, final Promise promise)
	{
		s_executor.submit(new Runnable() {
			@Override
			public void run() {
				String encrypt = aesGcmEncrypt(key, data, auth, iv);

				if( !encrypt.isEmpty() ) { promise.resolve(encrypt); }
				else { promise.reject(E_BAD_CERTIFICATE, "Encrypt failed!"); }
			}
		});
	}

	@ReactMethod
	public void aesDecrypt(final String key, final String data, final String auth, final String iv, final Promise promise)
	{
		s_executor.submit(new Runnable() {
			@Override
			public void run() {

				String decrypt = aesGcmDecrypt(key, data, auth, iv);

				if( !decrypt.isEmpty() ) { promise.resolve(decrypt); }
				else { promise.reject(E_BAD_CERTIFICATE, "Decrypt failed!"); }
			}
		});
    }

	@ReactMethod
	public void sha256(final String data, final Promise promise)
	{
	    s_executor.submit(new Runnable() {
			@Override
			public void run() {
				promise.resolve(sha256(data));
			}
		});
	}

	@ReactMethod
	public void getCertificates(final String companyID, final Promise promise)
	{
		s_executor.submit(new Runnable() {
			@Override
			public void run() {
				String ca = "-----BEGIN CERTIFICATE-----\n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\nsiYlaZh7ungNIY5HMT5+\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nMIIFoDCCA4igAwIBAgIBBTANBgkqhkiG9w0BAQsFADBgMQswCQYDVQQGEwJTSzEZ\nMBcGA1UECgwQRXhjYWxpYnVyIHMuci5vLjEaMBgGA1UECwwRRXhjYWxpYnVyIFJv\nb3QgQ0ExGjAYBgNVBAMMEUV4Y2FsaWJ1ciBSb290IENBMCAXDTE3MDkyNTEzMTMz\nMVoYDzIzMzMxMjMxMjM1OTU5WjBgMQswCQYDVQQGEwJTSzEZMBcGA1UECgwQRXhj\nYWxpYnVyIHMuci5vLjEaMBgGA1UECwwRRXhjYWxpYnVyIFJvb3QgQ0ExGjAYBgNV\nBAMMEUV4Y2FsaWJ1ciBSb290IENBMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIIC\nCgKCAgEAqUonlOX277jqyw6usNV8LQI0GnHOjH6ghEkm1Lvv97gTkg17/vCLlWxn\n7Z8sh6+PDjbicgJ9ERussjrwAvA2MCFNoAfSrHVb5y2qvp8HGIOLbPoMUgQs0L1E\ngggBD8S17YLxyiMpVc3WrClMNE62KXEP9g5OhnP8T0IIL+v+GMd6ha70xfp/RM7L\nWuv3nczJDRzt1gnXBXCcI+LaD/mUHSFPte8NdW2V6VC1p5L8UbvG2l0t3h7Zuw83\nqCAfHs224B6/Z6iJuvUDzIJ8EaQICS/OL2XRJAV90oRYJi60vcGN4SMwxDH5ZLHd\nhUy6spQ4GfYHnLbQ06lJ/6ErEwQvc3PktJS+v8WJVdkDIo0FqUbHV4nQvUwqN5b3\nD6ggJZ8fz3U04iYJsz5GA21sXAKIfLyHhlgvEVzSXSJtviOmJujrwur23wdPG9Ky\nff/5GO99UmP6c9HT0zFVGjpwG7EqMk2DGpdQxdJEE2rb2hn81WCLVpDdnLRCmyCC\nebknrn6Ln7+HkudACnFIaqiyAopEmNNEpyGaVoNfSWALqdaVCLq2lODL3L/jmkNR\nm/xmlV6NxOTdWW59+Nh807gZzZ6ZoxrjD2aPN5eKXQVLgrfZJ9iHGo/dvOei21Iv\nTklo3vi2jf0HzL3DXaXMD/whLwlYCK6eaHamcN3AskyJVvPlX5kCAwEAAaNjMGEw\nDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFIf0vdlB\nHTViMD8cllKhP+xYNG25MB8GA1UdIwQYMBaAFIf0vdlBHTViMD8cllKhP+xYNG25\nMA0GCSqGSIb3DQEBCwUAA4ICAQAYBLSg+5irZqHU6TRrM+GFHghF/JS828FpdiL6\nbpBkv3t6QDLUruSVABukiCQ5BorAu11aiU5amSMZ8cr6p43mZg2DTGfLd82rXUcC\nVlqmKuaMenahJrzGmpABtC7lHHzj/TiNoXHsjkYaI2meO5ZEgXJjLh18muIA8rkx\niZnqxF2t6kxIXAn1w5uKXJLmmIu8f8uy6OV9fnLNgEVrr5zKeoeaqwX2VVyxMTBu\naoXdMCo3mDK1vVx7mMZ9QK/pWQEJfUwEaJV+t7gLfIEQcPeqzzSjwO9OQzroGnmU\nehj4h0mPmWIUkmOrrBEhzx88xZew7iGItn9XfiWlT1H1LZmL+HDUj/gk3B7RprXg\nX+JVctWvCrtjoo2WWHR1YpFZ83/EjI3uOU2Y7wbgUT9IMkmIhsa1efGqXqZXsMX0\nmZZ1Y8Q9NoC7z332gNAbNHj5hUp44mrMBCCdQi3/1byAfgqLIx2PO229JBItL4fd\nystjyCyjiTO4D9ri+93+DT2FHy1OnDuBdAJZaREDZRgN7mVdKA0XhmqqcZWR1NFx\nsB5RvCne+ltng+7skEtQBd1x4jbO8A7Vbi19nioKERLF2OXacloNPSgaCa5qvbUm\nP55u+5aSk3+tm3xmni+88ck8mKw/gPffsJcrHdFiLO9kctEMCvzDy2CMKTTXSKJv\nGBrQaQ==\n-----END CERTIFICATE-----\n";
				String passphrase = sha512("ExcaliburEnterpriseToken").substring(0, 80);
				WritableMap map = new WritableNativeMap();
				map.putString("ca", ca);
				map.putString("passphrase", passphrase);

				if( RNExcaliburKeychainModule.exists(reactContext, companyID + "/excalibur.pfx") )
				{
					map.putString("pfx", RNExcaliburKeychainModule.loadString(reactContext, companyID + "/excalibur.pfx"));
				}
				else
				{
					String pfx = "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";

					map.putString("pfx", pfx);
				}

				promise.resolve(map);
			}
		});
	}

	@ReactMethod
	public void setCSRCertificate(final String companyID, final String cert, final Promise promise)
	{
		s_executor.submit(new Runnable() {
			@Override
			public void run() {
				String key = RNExcaliburKeychainModule.loadString(reactContext, companyID + "/excalibur.key");
				String passphrase = sha512("ExcaliburEnterpriseToken").substring(0, 80);

				if( !key.equals("") )
				{
					String pfx = p12(key, cert, passphrase);

					if( !pfx.equals("") )
					{
						if( RNExcaliburKeychainModule.saveString(reactContext,companyID + "/excalibur.pfx", pfx) )
						{
							RNExcaliburKeychainModule.remove(reactContext, companyID + "/excalibur.key");

							promise.resolve(true);
						}
						else
						{
							promise.reject("error", "cannot_save");
						}
					}
					else
					{
						promise.reject("error", "cannot_generate_pfx");
					}
				}
				else
				{
					promise.reject("error", "pem_not_exists");
				}
			}
		});
	}

	@ReactMethod
	public void generateCSR(final String companyID, final String deviceID, final String deviceType, final Promise promise)
	{
		s_executor.submit(new Runnable() {
			@Override
			public void run() {
				Object[] data = generateCSR(companyID, deviceID, deviceType);

				if( data.length == 0 )
				{
					promise.reject("error", "cannot_generate");
				}
				else
				{
					String privateKey = (String)data[0];
					String csr = (String)data[1];

					if( RNExcaliburKeychainModule.saveString(reactContext,companyID + "/excalibur.key", privateKey) )
					{
						promise.resolve(csr);
					}
					else
					{
						promise.reject("error", "cannot_save");
					}
				}
			}
		});
	}
	//endregion

	//region EMITTERS
	private void emitFactorStatus(String factor, String status, String data)
	{
		if( D ) Log.d(TAG, "factor (" + factor + ") status: "+status);

		WritableMap map = new WritableNativeMap();
		map.putString("factor", factor);

		if( !data.isEmpty() )
		{
			WritableMap statusMap = new WritableNativeMap();
			statusMap.putString("id", status);
			statusMap.putString("msg", data);

			map.putMap("status", statusMap);
		}
		else
		{
			map.putString("status", status);
		}

		reactContext
				.getJSModule(DeviceEventManagerModule.RCTDeviceEventEmitter.class)
				.emit(EMITTER_EVENT_FACTOR_STATUS, map);
	}
	//endregion

	//region NATIVE CALLS
	private native String aesGcmEncrypt(String key, String data, String auth, String iv);
	private native String aesGcmDecrypt(String key, String data, String auth, String iv);
	private native String privateEncrypt(String key, String passphrase, String data, String format);
    private native String privateDecrypt(String key, String passphrase, String data, String format);
	private native String publicEncrypt(String cert, String data, String format);
	private native String sha256(String data);
	private native String sha512(String data);
	private native String pbkdf2(String pass, String salt, int iterations);
	private native String p12(String key, String cert, String passphrase);
	private native String hexToBase64(String data);
	private native Object[] generateCSR(String companyID, String deviceID, String deviceType);
	//endregion

	//region FETCH
	private KeyStore getTrusKeystore( String ca )
	{
		KeyStore trusKeyStore = null;

		try
		{
			CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");

			String caCert = "-----BEGIN CERTIFICATE-----\nMIIFoDCCA4igAwIBAgIBBTANBgkqhkiG9w0BAQsFADBgMQswCQYDVQQGEwJTSzEZ\nMBcGA1UECgwQRXhjYWxpYnVyIHMuci5vLjEaMBgGA1UECwwRRXhjYWxpYnVyIFJv\nb3QgQ0ExGjAYBgNVBAMMEUV4Y2FsaWJ1ciBSb290IENBMCAXDTE3MDkyNTEzMTMz\nMVoYDzIzMzMxMjMxMjM1OTU5WjBgMQswCQYDVQQGEwJTSzEZMBcGA1UECgwQRXhj\nYWxpYnVyIHMuci5vLjEaMBgGA1UECwwRRXhjYWxpYnVyIFJvb3QgQ0ExGjAYBgNV\nBAMMEUV4Y2FsaWJ1ciBSb290IENBMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIIC\nCgKCAgEAqUonlOX277jqyw6usNV8LQI0GnHOjH6ghEkm1Lvv97gTkg17/vCLlWxn\n7Z8sh6+PDjbicgJ9ERussjrwAvA2MCFNoAfSrHVb5y2qvp8HGIOLbPoMUgQs0L1E\ngggBD8S17YLxyiMpVc3WrClMNE62KXEP9g5OhnP8T0IIL+v+GMd6ha70xfp/RM7L\nWuv3nczJDRzt1gnXBXCcI+LaD/mUHSFPte8NdW2V6VC1p5L8UbvG2l0t3h7Zuw83\nqCAfHs224B6/Z6iJuvUDzIJ8EaQICS/OL2XRJAV90oRYJi60vcGN4SMwxDH5ZLHd\nhUy6spQ4GfYHnLbQ06lJ/6ErEwQvc3PktJS+v8WJVdkDIo0FqUbHV4nQvUwqN5b3\nD6ggJZ8fz3U04iYJsz5GA21sXAKIfLyHhlgvEVzSXSJtviOmJujrwur23wdPG9Ky\nff/5GO99UmP6c9HT0zFVGjpwG7EqMk2DGpdQxdJEE2rb2hn81WCLVpDdnLRCmyCC\nebknrn6Ln7+HkudACnFIaqiyAopEmNNEpyGaVoNfSWALqdaVCLq2lODL3L/jmkNR\nm/xmlV6NxOTdWW59+Nh807gZzZ6ZoxrjD2aPN5eKXQVLgrfZJ9iHGo/dvOei21Iv\nTklo3vi2jf0HzL3DXaXMD/whLwlYCK6eaHamcN3AskyJVvPlX5kCAwEAAaNjMGEw\nDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFIf0vdlB\nHTViMD8cllKhP+xYNG25MB8GA1UdIwQYMBaAFIf0vdlBHTViMD8cllKhP+xYNG25\nMA0GCSqGSIb3DQEBCwUAA4ICAQAYBLSg+5irZqHU6TRrM+GFHghF/JS828FpdiL6\nbpBkv3t6QDLUruSVABukiCQ5BorAu11aiU5amSMZ8cr6p43mZg2DTGfLd82rXUcC\nVlqmKuaMenahJrzGmpABtC7lHHzj/TiNoXHsjkYaI2meO5ZEgXJjLh18muIA8rkx\niZnqxF2t6kxIXAn1w5uKXJLmmIu8f8uy6OV9fnLNgEVrr5zKeoeaqwX2VVyxMTBu\naoXdMCo3mDK1vVx7mMZ9QK/pWQEJfUwEaJV+t7gLfIEQcPeqzzSjwO9OQzroGnmU\nehj4h0mPmWIUkmOrrBEhzx88xZew7iGItn9XfiWlT1H1LZmL+HDUj/gk3B7RprXg\nX+JVctWvCrtjoo2WWHR1YpFZ83/EjI3uOU2Y7wbgUT9IMkmIhsa1efGqXqZXsMX0\nmZZ1Y8Q9NoC7z332gNAbNHj5hUp44mrMBCCdQi3/1byAfgqLIx2PO229JBItL4fd\nystjyCyjiTO4D9ri+93+DT2FHy1OnDuBdAJZaREDZRgN7mVdKA0XhmqqcZWR1NFx\nsB5RvCne+ltng+7skEtQBd1x4jbO8A7Vbi19nioKERLF2OXacloNPSgaCa5qvbUm\nP55u+5aSk3+tm3xmni+88ck8mKw/gPffsJcrHdFiLO9kctEMCvzDy2CMKTTXSKJv\nGBrQaQ==\n-----END CERTIFICATE-----\n";
			String intCert = "-----BEGIN CERTIFICATE-----\n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\nsiYlaZh7ungNIY5HMT5+\n-----END CERTIFICATE-----\n";

			trusKeyStore = KeyStore.getInstance(KeyStore.getDefaultType());
			trusKeyStore.load(null, null);

			// CA
			InputStream is = new ByteArrayInputStream( caCert.getBytes( Charset.forName("UTF-8") ) );
			Certificate cert = certificateFactory.generateCertificate(is);
			trusKeyStore.setCertificateEntry("exc-ca", cert);

			// INTERMEDIARY
			is = new ByteArrayInputStream( intCert.getBytes( Charset.forName("UTF-8") ) );
			cert = certificateFactory.generateCertificate(is);
			trusKeyStore.setCertificateEntry("exc-int", cert);

		} catch (KeyStoreException | CertificateException | NoSuchAlgorithmException | IOException e) {
			throw new RuntimeException(e);
		}

		return trusKeyStore;
	}

	private KeyStore getKeyKeystore( String pfx, String passphrase )
	{
		KeyStore keyKeyStore = null;

		try
		{
			byte[] data = Base64.decode( pfx, Base64.DEFAULT );

			InputStream is = new ByteArrayInputStream( data );

			keyKeyStore = KeyStore.getInstance("PKCS12");
			keyKeyStore.load(is, passphrase.toCharArray());

		} catch (KeyStoreException | CertificateException | NoSuchAlgorithmException | IOException e) {
			throw new RuntimeException(e);
		}

		return keyKeyStore;
	}

	private HttpsURLConnection getHttpsConnection(String url, ReadableMap certs)
	{
		String ca = certs.getString("ca");
		String pfx = certs.getString("pfx");
		String passphrase = certs.getString("passphrase");

		try
		{
			TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
			trustManagerFactory.init( getTrusKeystore(ca) );

			KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("PKIX");
			keyManagerFactory.init( getKeyKeystore(pfx, passphrase), passphrase.toCharArray() );

			SSLContext sslContext = SSLContext.getInstance("TLSv1.2");
			sslContext.init( keyManagerFactory.getKeyManagers(), trustManagerFactory.getTrustManagers(), null);

			X509TrustManager trustManager = (X509TrustManager) trustManagerFactory.getTrustManagers()[0];
			HostnameVerifier hostnameVerifier = new HostnameVerifier() {
				@Override
				public boolean verify(String hostname, SSLSession session) {
					return true;
				}
			};

			URL urlObj = new URL(url);
			HttpsURLConnection httpsConnection = (HttpsURLConnection) urlObj.openConnection();
			httpsConnection.setSSLSocketFactory( sslContext.getSocketFactory() );
			httpsConnection.setHostnameVerifier( hostnameVerifier );

			return httpsConnection;

		} catch (NoSuchAlgorithmException | KeyStoreException | KeyManagementException | UnrecoverableKeyException e) {
			throw new RuntimeException(e);
		} catch (MalformedURLException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}

		return null;
	}

	private HttpURLConnection getHttpConnection(String url)
	{
		try {
			URL urlObj = new URL(url);
			HttpURLConnection httpConnection = (HttpURLConnection) urlObj.openConnection();

			return httpConnection;

		} catch (MalformedURLException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}

		return null;
	}

	private void fetchRequest(String url, String data, ReadableMap certs, FetchCallbacks callbacks)
	{
		HttpURLConnection conn = certs == null ? getHttpConnection( url ) : getHttpsConnection( url, certs );

		try {
			// connection
			conn.setReadTimeout(10000);
			conn.setConnectTimeout(15000);
			conn.setRequestMethod("POST");
			conn.setRequestProperty("Content-Type", "application/json; charset=utf-8");
			conn.setDoInput(true);
			conn.setDoOutput(true);

			// request
			OutputStream os = conn.getOutputStream();
			BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(os, "UTF-8"));
			writer.write(data);
			writer.flush();
			writer.close();
			os.close();

			// response
			int responseCode=conn.getResponseCode();
			StringBuilder response = new StringBuilder();
			if (responseCode == HttpURLConnection.HTTP_OK) {
				String line;
				BufferedReader br=new BufferedReader(new InputStreamReader(conn.getInputStream()));
				while ((line=br.readLine()) != null) {
					response.append(line);
				}
			}
			conn.connect();

			// handle results
			if( D ) Log.d(TAG, "fetchRequest(): response="+response);
			callbacks.onSuccess(response.toString());

		} catch (IOException e) {
		    callbacks.onError(e);
		} finally {
			if(conn != null)
				conn.disconnect();
		}
	}
	//endregion

	private KeyStore getKeyStore() throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException
	{
		synchronized (keyStoreLock) {
			if (keyStore != null)
				return keyStore;

			keyStore = KeyStore.getInstance("AndroidKeyStore");
			keyStore.load(null);
		}
		return keyStore;
    }

	private void loadFactorKeys(String factor, FactorKeyPair factorKeyPair) throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException, UnrecoverableKeyException, InvalidKeyException, BadPaddingException, NoSuchPaddingException, IllegalBlockSizeException, InvalidKeySpecException
	{
		if ( KEYSTORE_API_AVAILABLE )
		{
			PrivateKey privateKey = (PrivateKey) getKeyStore().getKey(factorAlias(factor), null);
			PublicKey publicKey = getKeyStore().getCertificate(factorAlias(factor)).getPublicKey();

			factorKeyPair.setPrivateKey( privateKey );
			factorKeyPair.setPublicKey( publicKey );
		}
		else
		{
			byte[] encodedPublicKey = RNExcaliburKeychainModule.load(reactContext, factorAlias(factor) + ".public" );
			byte[] encodedPrivateKey = RNExcaliburKeychainModule.load(reactContext, factorAlias(factor) + ".private" );

			X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(encodedPublicKey);
			PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(encodedPrivateKey);

			KeyFactory keyFactory = KeyFactory.getInstance("RSA");

			PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
			PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);

			factorKeyPair.setPrivateKey( privateKey );
			factorKeyPair.setPublicKey( publicKey );
		}
	}

	private boolean hasFactorHash(String factor)
	{
		return ! RNExcaliburKeychainModule.loadString(reactContext,factor + ".hash").isEmpty();
	}

    private boolean hasGeneratedKeys(String factor)
	{
		boolean hasCert = false;

		if ( KEYSTORE_API_AVAILABLE )
		{
			try
			{
				hasCert = getKeyStore().containsAlias( factorAlias(factor) );
			}
			catch (KeyStoreException | CertificateException | NoSuchAlgorithmException | IOException e)
			{/* any exception = not certs */}
		}
		else
		{
			hasCert =
					RNExcaliburKeychainModule.exists( reactContext,factorAlias(factor) + ".private" ) &&
					RNExcaliburKeychainModule.exists( reactContext,factorAlias(factor) + ".public" );
		}

		return hasCert;
	}

    @SuppressLint("MissingPermission")
	private boolean isFingerprintAvailableAndEnrolled()
	{
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            FingerprintManager fingerprintManager =
                    (FingerprintManager) reactContext.getSystemService(Context.FINGERPRINT_SERVICE);

            if(fingerprintManager==null)
                return false;
            else
                return fingerprintManager.isHardwareDetected() &&
                        fingerprintManager.hasEnrolledFingerprints();

        } else {
            return false;
        }
    }

    private WritableMap getCompanyCertificates( String companyID )
	{
		String certificates = RNExcaliburKeychainModule.loadString(reactContext,companyID + "/certificates.json");

		String ca = "-----BEGIN CERTIFICATE-----\n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\nsiYlaZh7ungNIY5HMT5+\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nMIIFoDCCA4igAwIBAgIBBTANBgkqhkiG9w0BAQsFADBgMQswCQYDVQQGEwJTSzEZ\nMBcGA1UECgwQRXhjYWxpYnVyIHMuci5vLjEaMBgGA1UECwwRRXhjYWxpYnVyIFJv\nb3QgQ0ExGjAYBgNVBAMMEUV4Y2FsaWJ1ciBSb290IENBMCAXDTE3MDkyNTEzMTMz\nMVoYDzIzMzMxMjMxMjM1OTU5WjBgMQswCQYDVQQGEwJTSzEZMBcGA1UECgwQRXhj\nYWxpYnVyIHMuci5vLjEaMBgGA1UECwwRRXhjYWxpYnVyIFJvb3QgQ0ExGjAYBgNV\nBAMMEUV4Y2FsaWJ1ciBSb290IENBMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIIC\nCgKCAgEAqUonlOX277jqyw6usNV8LQI0GnHOjH6ghEkm1Lvv97gTkg17/vCLlWxn\n7Z8sh6+PDjbicgJ9ERussjrwAvA2MCFNoAfSrHVb5y2qvp8HGIOLbPoMUgQs0L1E\ngggBD8S17YLxyiMpVc3WrClMNE62KXEP9g5OhnP8T0IIL+v+GMd6ha70xfp/RM7L\nWuv3nczJDRzt1gnXBXCcI+LaD/mUHSFPte8NdW2V6VC1p5L8UbvG2l0t3h7Zuw83\nqCAfHs224B6/Z6iJuvUDzIJ8EaQICS/OL2XRJAV90oRYJi60vcGN4SMwxDH5ZLHd\nhUy6spQ4GfYHnLbQ06lJ/6ErEwQvc3PktJS+v8WJVdkDIo0FqUbHV4nQvUwqN5b3\nD6ggJZ8fz3U04iYJsz5GA21sXAKIfLyHhlgvEVzSXSJtviOmJujrwur23wdPG9Ky\nff/5GO99UmP6c9HT0zFVGjpwG7EqMk2DGpdQxdJEE2rb2hn81WCLVpDdnLRCmyCC\nebknrn6Ln7+HkudACnFIaqiyAopEmNNEpyGaVoNfSWALqdaVCLq2lODL3L/jmkNR\nm/xmlV6NxOTdWW59+Nh807gZzZ6ZoxrjD2aPN5eKXQVLgrfZJ9iHGo/dvOei21Iv\nTklo3vi2jf0HzL3DXaXMD/whLwlYCK6eaHamcN3AskyJVvPlX5kCAwEAAaNjMGEw\nDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFIf0vdlB\nHTViMD8cllKhP+xYNG25MB8GA1UdIwQYMBaAFIf0vdlBHTViMD8cllKhP+xYNG25\nMA0GCSqGSIb3DQEBCwUAA4ICAQAYBLSg+5irZqHU6TRrM+GFHghF/JS828FpdiL6\nbpBkv3t6QDLUruSVABukiCQ5BorAu11aiU5amSMZ8cr6p43mZg2DTGfLd82rXUcC\nVlqmKuaMenahJrzGmpABtC7lHHzj/TiNoXHsjkYaI2meO5ZEgXJjLh18muIA8rkx\niZnqxF2t6kxIXAn1w5uKXJLmmIu8f8uy6OV9fnLNgEVrr5zKeoeaqwX2VVyxMTBu\naoXdMCo3mDK1vVx7mMZ9QK/pWQEJfUwEaJV+t7gLfIEQcPeqzzSjwO9OQzroGnmU\nehj4h0mPmWIUkmOrrBEhzx88xZew7iGItn9XfiWlT1H1LZmL+HDUj/gk3B7RprXg\nX+JVctWvCrtjoo2WWHR1YpFZ83/EjI3uOU2Y7wbgUT9IMkmIhsa1efGqXqZXsMX0\nmZZ1Y8Q9NoC7z332gNAbNHj5hUp44mrMBCCdQi3/1byAfgqLIx2PO229JBItL4fd\nystjyCyjiTO4D9ri+93+DT2FHy1OnDuBdAJZaREDZRgN7mVdKA0XhmqqcZWR1NFx\nsB5RvCne+ltng+7skEtQBd1x4jbO8A7Vbi19nioKERLF2OXacloNPSgaCa5qvbUm\nP55u+5aSk3+tm3xmni+88ck8mKw/gPffsJcrHdFiLO9kctEMCvzDy2CMKTTXSKJv\nGBrQaQ==\n-----END CERTIFICATE-----\n";

		if( certificates.isEmpty() )
		{
			String pfx = "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";
			String passphrase = sha512("ExcaliburEnterpriseToken").substring(0, 80);

			WritableMap res = new WritableNativeMap();
			res.putString("ca", ca);
			res.putString("pfx", pfx);
			res.putString("passphrase", passphrase);

			return res;
		}
		else
		{
			WritableMap res = new WritableNativeMap();

			try {

				JSONObject certs_dict = new JSONObject(certificates);

				res.putString("ca", ca + certs_dict.getString("server"));
				res.putString("pfx", certs_dict.getString("pfx"));
				res.putString("passphrase", certs_dict.getString("passphrase"));

			} catch (JSONException e) {
				e.printStackTrace();
			}

			return res;
		}
	}

	private void generateFactorCertificate(String factor) throws NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, RuntimeException, InvalidKeyException, BadPaddingException, NoSuchPaddingException, IllegalBlockSizeException, IOException
	{
		if ( KEYSTORE_API_AVAILABLE )
		{
			KeyPairGenerator keyPairGenerator =
					KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore");

			KeyGenParameterSpec.Builder keyGenParameterSpecBuilder = new KeyGenParameterSpec
					.Builder(factorAlias(factor), KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
					.setDigests(KeyProperties.DIGEST_SHA256)
					.setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1);

			//if( factor.equals("fingerprint") )
			//	keyGenParameterSpecBuilder
			//			.setUserAuthenticationRequired(true)
			//			.setUserAuthenticationValidityDurationSeconds(-1);

			keyPairGenerator.initialize(keyGenParameterSpecBuilder.build());
			keyPairGenerator.generateKeyPair();

			if( D ) Log.d(TAG, "Certificate (keystore) for factor " + factor + " was generated!");
		}
		else
		{
			RSAKeyGenParameterSpec rsaSpec = new RSAKeyGenParameterSpec( 2048, RSAKeyGenParameterSpec.F4 );

			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
			keyPairGenerator.initialize(rsaSpec);

			KeyPair keyPair = keyPairGenerator.generateKeyPair();

			X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec( keyPair.getPublic().getEncoded() );
			PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec( keyPair.getPrivate().getEncoded() );

			RNExcaliburKeychainModule.save(reactContext,factorAlias(factor) + ".private", privateKeySpec.getEncoded() );
			RNExcaliburKeychainModule.save(reactContext,factorAlias(factor) + ".public", publicKeySpec.getEncoded() );

			if( D ) Log.d(TAG, "Certificate (keychains) for factor " + factor + " was generated!");
		}
	}

	@SuppressLint("MissingPermission")
	private void signFactorData(String factor, FactorKeyPair keyPair, final String intent, final String data, CancellationSignal cancellationSignal, final SigningCallbacks signingCallbacks)
	{
		try {
			final Signature s = Signature.getInstance(SIGNATURE_ALG);
			s.initSign(keyPair.getPrivateKey());

			/*
			//
			//    USE FINGERPRINT
			//
			if(factor.equals("fingerprint") && isFingerprintAvailableAndEnrolled()){
				if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
					signingCallbacks.onInitialized();
					FingerprintManager.CryptoObject cryptoObject = new FingerprintManager.CryptoObject(s);
					FingerprintManager fingerprintManager = (FingerprintManager) reactContext.getSystemService(Context.FINGERPRINT_SERVICE);
					fingerprintManager.authenticate(
                            cryptoObject,
                            cancellationSignal,
                            0,
                            new FingerprintManager.AuthenticationCallback() {
                                @Override
                                public void onAuthenticationError(int errorCode, CharSequence errString) {
                                    super.onAuthenticationError(errorCode, errString);
                                    signingCallbacks.onAuthenticationError(errorCode, (String) errString);
                                }

                                @Override
                                public void onAuthenticationHelp(int helpCode, CharSequence helpString) {
                                    super.onAuthenticationHelp(helpCode, helpString);
                                    signingCallbacks.onAuthenticationHelp(helpCode, (String) helpString);
                                }

                                @Override
                                public void onAuthenticationSucceeded(FingerprintManager.AuthenticationResult result) {
                                    super.onAuthenticationSucceeded(result);

                                    try {
                                        // sign intent
										s.update(intent.getBytes());
										String intentSignature = Base64.encodeToString(s.sign(), Base64.NO_WRAP);

										// sign data
										String dataSignature = "";
										if(data!=null && !data.isEmpty()) {
											s.update(data.getBytes());
											dataSignature = Base64.encodeToString(s.sign(), Base64.NO_WRAP);
										}

										signingCallbacks.onSigned(intentSignature, dataSignature);
                                    } catch (SignatureException e) {
                                        signingCallbacks.onSignError(e);
                                    }
                                }

                                @Override
                                public void onAuthenticationFailed() {
                                    super.onAuthenticationFailed();
                                    signingCallbacks.onAuthenticationFailed();
                                }
                            },
                            null);
				}
			}
			//
			//    WITHOUT FINGERPRINT
			//
			else {

			*/
				if( ! factor.equals("fingerprint") )
					signingCallbacks.onInitialized();

				// sign intent
				s.update(intent.getBytes());
				String intentSignature = Base64.encodeToString(s.sign(), Base64.NO_WRAP);

				// sign data
				String dataSignature = "";
				if(data!=null && !data.isEmpty()) {
					s.update(data.getBytes());
					dataSignature = Base64.encodeToString(s.sign(), Base64.NO_WRAP);
				}

				signingCallbacks.onSigned(intentSignature, dataSignature);
//			}

		} catch (InvalidKeyException | NoSuchAlgorithmException | SignatureException e) {
		    signingCallbacks.onSignError(e);
		}
	}

    private String factorAlias(String factor)
	{
    	return "excalibur-" + factor;
	}

	private String convertToPem(PublicKey publicKey)
	{
        String cert_begin = "-----BEGIN PUBLIC KEY-----\n";
        String end_cert = "-----END PUBLIC KEY-----";

        byte[] derCert = publicKey.getEncoded();
        String pemCertPre = Base64.encodeToString(derCert, Base64.DEFAULT);
        String pemCert = cert_begin + pemCertPre + end_cert;

        return pemCert;
    }

    private String convertToPem(PrivateKey privateKey)
	{
		String cert_begin = "-----BEGIN PRIVATE KEY-----\n";
        String end_cert = "-----END PRIVATE KEY-----";

        byte[] derCert = privateKey.getEncoded();
        String pemCertPre = Base64.encodeToString(derCert, Base64.DEFAULT);
        String pemCert = cert_begin + pemCertPre + end_cert;

        return pemCert;
	}

    private class FactorKeyPair
	{
		PublicKey publicKey;
		PrivateKey privateKey;

		public PublicKey getPublicKey() {
			return publicKey;
		}

		public void setPublicKey(PublicKey publicKey) {
			this.publicKey = publicKey;
		}

		public PrivateKey getPrivateKey() {
			return privateKey;
		}

		public void setPrivateKey(PrivateKey privateKey) {
			this.privateKey = privateKey;
		}
	}

    private interface SigningCallbacks
	{
    	void onInitialized();
	    void onSigned(String signature, String dataSignature);
	    void onSignError(Exception e);
	    void onAuthenticationFailed();
	    void onAuthenticationError(int errorCode, String errString);
		void onAuthenticationHelp(int helpCode, String helpString);
	}

	private interface FetchCallbacks
	{
    	void onSuccess(String results);
    	void onError(Exception e);
	}
}
