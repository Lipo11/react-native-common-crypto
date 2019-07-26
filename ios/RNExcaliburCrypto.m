
#import "RNExcaliburCrypto.h"
#import "RNExcaliburCrypto-Swift.h"
#import "Storage.h"
#import "ExcaliburOpenSSL.h"
#import "ExcaliburConnection.h"

@interface RNExcaliburCrypto()

@property (strong, atomic) SecureEnclave * secureEnclave;

@end

@implementation RNExcaliburCrypto

RCT_EXPORT_MODULE()

@synthesize secureEnclave = _secureEnclave;

- (id)init
{
    self = [super init];
    
    if( self )
    {
        _secureEnclave = [[SecureEnclave alloc] init];
    }
    
    return self;
}

+ (BOOL)requiresMainQueueSetup
{
    return NO;
}

- (NSArray<NSString *> *)supportedEvents
{
    return @[@"factorStatus"];
}

#pragma mark - User RSA

RCT_REMAP_METHOD(fetch,
                 url:(NSString *)url
                 data:(NSString *)data
                 options:(NSDictionary *)options
                 fetchResolver:(RCTPromiseResolveBlock)resolve
                 fetchRejecter:(RCTPromiseRejectBlock)reject)
{
    if( [options objectForKey:@"company-id"] != nil )
    {
        options = [self getCompanyCertificates:[options objectForKey:@"company-id"]];
    }
    
    ExcaliburConnection * conn = [[ExcaliburConnection alloc] init];
    [conn startWithURL:url data:data options:options callback:^(BOOL status, NSString * response)
    {
        if( status )
        {
            resolve(response);
        }
        else
        {
            reject(@"error", response, nil);
        }
    }];
}

RCT_REMAP_METHOD(setUserCertificate,
                 companyID:(NSString *)companyID
                 name:(NSString *)name
                 cert:(NSString *)cert
                 key:(NSString *)key
                 pass:(NSString *)pass
                 setUserResolver:(RCTPromiseResolveBlock)resolve
                 setUserRejecter:(RCTPromiseRejectBlock)reject)
{
    Boolean saved = true;
    
    if( ![cert isEqualToString:@""] )
    {
        saved = [Storage write:cert to:[NSString stringWithFormat:@"%@/certificates/user-%@.crt", companyID, name]];
    }
    
    if( ![key isEqualToString:@""] )
    {
        saved = saved && [Storage write:key to:[NSString stringWithFormat:@"%@/certificates/user-%@.key", companyID, name]];
    }
    
    if( ![pass isEqualToString:@""] )
    {
        NSString * passphrase = [[ExcaliburOpenSSL sha512With:pass] substringWithRange:NSMakeRange(0, 80)];
        saved = saved && [Storage write:passphrase to:[NSString stringWithFormat:@"%@/certificates/user-%@.pass", companyID, name]];
    }
    
    if( saved )
    {
        resolve([NSNumber numberWithBool:YES]);
    }
    else
    {
        reject(@"error", @"not_saved", nil);
    }
}

RCT_REMAP_METHOD(getUserCertificate,
                 companyID:(NSString *)companyID
                 name:(NSString *)name
                 getUserResolver:(RCTPromiseResolveBlock)resolve
                 getUserRejecter:(RCTPromiseRejectBlock)reject)
{
    NSString * cert = [Storage read:[NSString stringWithFormat:@"%@/certificates/user-%@.crt", companyID, name]];
    
    if( ![cert isEqualToString:@""] )
    {
        resolve(cert);
    }
    else
    {
        reject(@"error", @"unknown_user", nil);
    }
}

RCT_REMAP_METHOD(getUserCertificateHash,
                 companyID:(NSString *)companyID
                 name:(NSString *)name
                 getUserHashResolver:(RCTPromiseResolveBlock)resolve
                 getUserHashRejecter:(RCTPromiseRejectBlock)reject)
{
    NSString * cert = [Storage read:[NSString stringWithFormat:@"%@/certificates/user-%@.crt", companyID, name]];
    
    if( ![cert isEqualToString:@""] )
    {
        resolve([ExcaliburOpenSSL hexToBase64With:[ExcaliburOpenSSL sha256With:cert]]);
    }
    else
    {
        reject(@"error", @"unknown_user", nil);
    }
}

RCT_REMAP_METHOD(signWithUserCertificate,
                 companyID:(NSString *)companyID
                 name:(NSString *)name
                 data:(NSString *)data
                 format:(NSString *)format
                 signUserResolver:(RCTPromiseResolveBlock)resolve
                 signUserRejecter:(RCTPromiseRejectBlock)reject)
{
    NSString * cert = [Storage read:[NSString stringWithFormat:@"%@/certificates/user-%@.crt", companyID, name]];
    NSString * key = [Storage read:[NSString stringWithFormat:@"%@/certificates/user-%@.key", companyID, name]];
    NSString * pass = [Storage read:[NSString stringWithFormat:@"%@/certificates/user-%@.pass", companyID, name]];
    
    if( ![key isEqualToString:@""] && ![pass isEqualToString:@""] )
    {
        NSString * sign = [ExcaliburOpenSSL privateEncryptWith:key passphrase:pass data:data format:format];
        
        if( ![sign isEqualToString:@""] )
        {
            resolve(sign);
        }
        else
        {
            reject(@"error", @"bad_certificate", nil);
        }
    }
    else if( ![cert isEqualToString:@""] )
    {
        NSString * sign = [ExcaliburOpenSSL publicEncryptWith:cert data:data format:format];
        
        if( ![sign isEqualToString:@""] )
        {
            resolve(sign);
        }
        else
        {
            reject(@"error", @"bad_certificate", nil);
        }
    }
    else
    {
        reject(@"error", @"unknown_user", nil);
    }
}

RCT_REMAP_METHOD(privateDecryptWithUserCertificate,
                 companyID:(NSString *)companyID
                 name:(NSString *)name
                 data:(NSString *)data
                 format:(NSString *)format
                 privateDecryptResolver:(RCTPromiseResolveBlock)resolve
                 privateDecryptRejecter:(RCTPromiseRejectBlock)reject)
{
    NSString * key = [Storage read:[NSString stringWithFormat:@"%@/certificates/user-%@.key", companyID, name]];
    NSString * pass = [Storage read:[NSString stringWithFormat:@"%@/certificates/user-%@.pass", companyID, name]];
    
    if( ![key isEqualToString:@""] && ![pass isEqualToString:@""] )
    {
        NSString * sign = [ExcaliburOpenSSL privateDecryptWith:key passphrase:pass data:data format:format];
        
        if( ![sign isEqualToString:@""] )
        {
            resolve(sign);
        }
        else
        {
            reject(@"error", @"bad_certificate", nil);
        }
    }
    else
    {
        reject(@"error", @"unknown_user", nil);
    }
}

RCT_REMAP_METHOD(verifyWithUserCertificate,
                 companyID:(NSString *)companyID
                 name:(NSString *)name
                 data:(NSString *)data
                 format:(NSString *)format
                 verifyUserResolver:(RCTPromiseResolveBlock)resolve
                 verifyUserRejecter:(RCTPromiseRejectBlock)reject)
{
    //NSString * cert = [Storage read:[NSString stringWithFormat:@"%lld/certificates/user.crt", userID]];
    //NSString * pass = [Storage read:[NSString stringWithFormat:@"%lld/certificates/user.pass", userID]];
    
    resolve(@{ @"ok": [NSNumber numberWithBool:YES] });
}

#pragma mark - Factors EC keys

RCT_REMAP_METHOD(removeFactorsCertificates,
                 factors:(NSArray *)factors
                 removeFactorsResolver:(RCTPromiseResolveBlock)resolve
                 removeFactorsRejecter:(RCTPromiseRejectBlock)reject)
{
    BOOL result = YES;
    
    for( NSString * factor in factors )
    {
        BOOL deleteFactor = [_secureEnclave deletePair:factor];
        
        if( result ){ result = deleteFactor; }
    }
    
    if( result ){ resolve(@YES); }
    else{ reject(@"error", @"remove_factors_error", nil); }
}

RCT_REMAP_METHOD(generateFactorCertificate,
                 factor:(NSString *)factor
                 generateFactorResolver:(RCTPromiseResolveBlock)resolve
                 generateFactorRejecter:(RCTPromiseRejectBlock)reject)
{
    [_secureEnclave generatePair:factor callback:^( BOOL generated )
    {
        if( generated )
        {
            resolve(@YES);
        }
        else
        {
            reject(@"error", @"unknown_error", nil);
        }
    }];
}

RCT_REMAP_METHOD(getFactorPublicKey,
                 factor:(NSString *)factor
                 intent:(NSString *)intent
                 text:(NSString *)text
                 data:(NSString *)data
                 factorPublicKeyResolver:(RCTPromiseResolveBlock)resolve
                 factorPublicKeyRejecter:(RCTPromiseRejectBlock)reject)
{
    [self sendEventWithName:@"factorStatus" body:@{ @"factor": factor, @"status": @"initialized" }];
    
    if( [factor isEqualToString:@"pin"] )
    {
        NSData * intentData = [intent dataUsingEncoding:NSUTF8StringEncoding];
        NSDictionary * json = [NSJSONSerialization JSONObjectWithData:intentData options:0 error:nil];
        
        NSString * userID = [json objectForKey:@"userID"];
        NSString * deviceID = [[UIDevice currentDevice] identifierForVendor].UUIDString;
        
        NSString * userIDHash = [ExcaliburOpenSSL pbkdf2With:data salt:userID iterations:10000];
        NSString * deviceIDHash = [ExcaliburOpenSSL pbkdf2With:data salt:deviceID iterations:10000];
        
        [Storage write:deviceIDHash to:[NSString stringWithFormat:@"%@.hash", factor]];
        
        data = [NSString stringWithFormat:@"{\"hash\":\"%@\"}", userIDHash];
    }
    
    [_secureEnclave getPublicKey:factor intent:intent data:data text:text callback:^( NSString * publicKey, NSString * signature, NSString * dataSignature )
    {
        if( ![publicKey isEqualToString:@""] )
        {
            NSMutableDictionary * result = [@{ @"public-key": publicKey, @"signature": signature, @"algorithm": @"EC-SHA256" } mutableCopy];
            
            if( ![data isEqualToString:@""] )
            {
                NSData * dataJsonData = [data dataUsingEncoding:NSUTF8StringEncoding];
                NSMutableDictionary * dataJson = [[NSJSONSerialization JSONObjectWithData:dataJsonData options:0 error:nil] mutableCopy];
                [dataJson setObject:dataSignature forKey:@"signature"];
                
                [result setObject:dataJson forKey:factor];
            }
            
            resolve(result);
        }
        else
        {
            reject(@"error", signature, nil);
        }
    }];
}

RCT_REMAP_METHOD(signWithFactor,
                 factor:(NSString *)factor
                 intent:(NSString *)intent
                 text:(NSString *)text
                 data:(NSString *)data
                 factorSignResolver:(RCTPromiseResolveBlock)resolve
                 factorSignRejecter:(RCTPromiseRejectBlock)reject)
{
    [self sendEventWithName:@"factorStatus" body:@{ @"factor": factor, @"status": @"initialized" }];
    
    if( [factor isEqualToString:@"pin"] )
    {
        NSData * intentData = [intent dataUsingEncoding:NSUTF8StringEncoding];
        NSDictionary * json = [NSJSONSerialization JSONObjectWithData:intentData options:0 error:nil];
        
        NSString * userID = [json objectForKey:@"userID"];
        NSString * deviceID = [[UIDevice currentDevice] identifierForVendor].UUIDString;
        
        NSString * userIDHash = [ExcaliburOpenSSL pbkdf2With:data salt:userID iterations:10000];
        NSString * deviceIDHash = [ExcaliburOpenSSL pbkdf2With:data salt:deviceID iterations:10000];
        NSString * savedHash = [Storage read:[NSString stringWithFormat:@"%@.hash", factor]];
        
        if( ![deviceIDHash isEqualToString:savedHash] )
        {
            reject(@"error", @"bad_pin", nil);
            
            return;
        }
        
        data = [NSString stringWithFormat:@"{\"hash\":\"%@\"}", userIDHash];
    }
    
    [_secureEnclave sign:factor intent:intent data:data text:text callback:^( NSString * signature, NSString * dataSignature )
    {
        if( ![signature isEqualToString:@""] )
        {
            NSMutableDictionary * result = [@{ @"signature": signature } mutableCopy];
            
            if( ![data isEqualToString:@""] )
            {
                NSData * dataJsonData = [data dataUsingEncoding:NSUTF8StringEncoding];
                NSMutableDictionary * dataJson = [[NSJSONSerialization JSONObjectWithData:dataJsonData options:0 error:nil] mutableCopy];
                [dataJson setObject:dataSignature forKey:@"signature"];
                
                [result setObject:dataJson forKey:factor];
            }
            
            resolve(result);
        }
        else
        {
            reject(@"error", dataSignature, nil);
        }
    }];
}

RCT_REMAP_METHOD(isFactorInitialized,
                 factor:(NSString *)factor
                 factorInitializedResolver:(RCTPromiseResolveBlock)resolve
                 factorInitializedRejecter:(RCTPromiseRejectBlock)reject)
{
    BOOL exists = ( [factor isEqualToString:@"pin"] ? [Storage exists:[NSString stringWithFormat:@"%@.hash", factor]] : YES );
    
    resolve(@{
                @"initialized": [NSNumber numberWithBool:exists && [_secureEnclave existsPrivateCertificate:factor]],
                @"available": [NSNumber numberWithBool:[_secureEnclave available:factor]]
            });
}

RCT_REMAP_METHOD(isPinFactorCorrect,
                 pin:(NSString *)pin
                 pinCorrectResolver:(RCTPromiseResolveBlock)resolve
                 pinCorrectRejecter:(RCTPromiseRejectBlock)reject)
{
    NSString * deviceID = [[UIDevice currentDevice] identifierForVendor].UUIDString;
    NSString * deviceIDHash = [ExcaliburOpenSSL pbkdf2With:pin salt:deviceID iterations:10000];
    NSString * savedHash = [Storage read:[NSString stringWithFormat:@"%@.hash", @"pin"]];
    
    resolve([NSNumber numberWithBool:[deviceIDHash isEqualToString:savedHash]]);
}

RCT_REMAP_METHOD(cancelFactor,
                 factor:(NSString *)factor
                 cancelResolver:(RCTPromiseResolveBlock)resolve
                 cancelRejecter:(RCTPromiseRejectBlock)reject)
{
    [_secureEnclave closeBiometrics];
    
    resolve(@{ @"ok": [NSNumber numberWithBool:YES] });
}

#pragma mark - Load company certificates

- (NSDictionary *)getCompanyCertificates:(NSString *)companyID
{
    NSString * certificates = [Storage read:[NSString stringWithFormat:@"%@/certificates.json", companyID]];
    
    NSString * ca = @"-----BEGIN CERTIFICATE-----\n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\nsiYlaZh7ungNIY5HMT5+\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nMIIFoDCCA4igAwIBAgIBBTANBgkqhkiG9w0BAQsFADBgMQswCQYDVQQGEwJTSzEZ\nMBcGA1UECgwQRXhjYWxpYnVyIHMuci5vLjEaMBgGA1UECwwRRXhjYWxpYnVyIFJv\nb3QgQ0ExGjAYBgNVBAMMEUV4Y2FsaWJ1ciBSb290IENBMCAXDTE3MDkyNTEzMTMz\nMVoYDzIzMzMxMjMxMjM1OTU5WjBgMQswCQYDVQQGEwJTSzEZMBcGA1UECgwQRXhj\nYWxpYnVyIHMuci5vLjEaMBgGA1UECwwRRXhjYWxpYnVyIFJvb3QgQ0ExGjAYBgNV\nBAMMEUV4Y2FsaWJ1ciBSb290IENBMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIIC\nCgKCAgEAqUonlOX277jqyw6usNV8LQI0GnHOjH6ghEkm1Lvv97gTkg17/vCLlWxn\n7Z8sh6+PDjbicgJ9ERussjrwAvA2MCFNoAfSrHVb5y2qvp8HGIOLbPoMUgQs0L1E\ngggBD8S17YLxyiMpVc3WrClMNE62KXEP9g5OhnP8T0IIL+v+GMd6ha70xfp/RM7L\nWuv3nczJDRzt1gnXBXCcI+LaD/mUHSFPte8NdW2V6VC1p5L8UbvG2l0t3h7Zuw83\nqCAfHs224B6/Z6iJuvUDzIJ8EaQICS/OL2XRJAV90oRYJi60vcGN4SMwxDH5ZLHd\nhUy6spQ4GfYHnLbQ06lJ/6ErEwQvc3PktJS+v8WJVdkDIo0FqUbHV4nQvUwqN5b3\nD6ggJZ8fz3U04iYJsz5GA21sXAKIfLyHhlgvEVzSXSJtviOmJujrwur23wdPG9Ky\nff/5GO99UmP6c9HT0zFVGjpwG7EqMk2DGpdQxdJEE2rb2hn81WCLVpDdnLRCmyCC\nebknrn6Ln7+HkudACnFIaqiyAopEmNNEpyGaVoNfSWALqdaVCLq2lODL3L/jmkNR\nm/xmlV6NxOTdWW59+Nh807gZzZ6ZoxrjD2aPN5eKXQVLgrfZJ9iHGo/dvOei21Iv\nTklo3vi2jf0HzL3DXaXMD/whLwlYCK6eaHamcN3AskyJVvPlX5kCAwEAAaNjMGEw\nDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFIf0vdlB\nHTViMD8cllKhP+xYNG25MB8GA1UdIwQYMBaAFIf0vdlBHTViMD8cllKhP+xYNG25\nMA0GCSqGSIb3DQEBCwUAA4ICAQAYBLSg+5irZqHU6TRrM+GFHghF/JS828FpdiL6\nbpBkv3t6QDLUruSVABukiCQ5BorAu11aiU5amSMZ8cr6p43mZg2DTGfLd82rXUcC\nVlqmKuaMenahJrzGmpABtC7lHHzj/TiNoXHsjkYaI2meO5ZEgXJjLh18muIA8rkx\niZnqxF2t6kxIXAn1w5uKXJLmmIu8f8uy6OV9fnLNgEVrr5zKeoeaqwX2VVyxMTBu\naoXdMCo3mDK1vVx7mMZ9QK/pWQEJfUwEaJV+t7gLfIEQcPeqzzSjwO9OQzroGnmU\nehj4h0mPmWIUkmOrrBEhzx88xZew7iGItn9XfiWlT1H1LZmL+HDUj/gk3B7RprXg\nX+JVctWvCrtjoo2WWHR1YpFZ83/EjI3uOU2Y7wbgUT9IMkmIhsa1efGqXqZXsMX0\nmZZ1Y8Q9NoC7z332gNAbNHj5hUp44mrMBCCdQi3/1byAfgqLIx2PO229JBItL4fd\nystjyCyjiTO4D9ri+93+DT2FHy1OnDuBdAJZaREDZRgN7mVdKA0XhmqqcZWR1NFx\nsB5RvCne+ltng+7skEtQBd1x4jbO8A7Vbi19nioKERLF2OXacloNPSgaCa5qvbUm\nP55u+5aSk3+tm3xmni+88ck8mKw/gPffsJcrHdFiLO9kctEMCvzDy2CMKTTXSKJv\nGBrQaQ==\n-----END CERTIFICATE-----\n";
    
    if( [certificates isEqualToString:@""] )
    {
        NSString * pfx = @"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";
        NSString * passphrase = [[ExcaliburOpenSSL sha512With:@"ExcaliburEnterpriseToken"] substringWithRange:NSMakeRange(0, 80)];
        
        return @{ @"ca": ca, @"pfx": pfx, @"passphrase": passphrase };
    }
    else
    {
        NSError * error;
        NSData * certs_data = [certificates dataUsingEncoding:NSUTF8StringEncoding];
        NSDictionary * certs_dict = [NSJSONSerialization JSONObjectWithData:certs_data options:NSJSONReadingMutableContainers error:&error];
        
        return @{ @"ca": [ca stringByAppendingString:[certs_dict objectForKey:@"server"]], @"pfx": [certs_dict objectForKey:@"pfx"], @"passphrase": [certs_dict objectForKey:@"passphrase"] };
    }
}

RCT_REMAP_METHOD(getCompanyCertificates,
                 companyID:(NSString *)companyID
                 getCompanyCertificatesResolver:(RCTPromiseResolveBlock)resolve
                 getCompanyCertificatesRejecter:(RCTPromiseRejectBlock)reject)
{
    resolve([self getCompanyCertificates:companyID]);
}

RCT_REMAP_METHOD(setCompanyCertificates,
                 companyID:(NSString *)companyID
                 certificates:(NSDictionary *)certificates
                 setCompanyCertificatesResolver:(RCTPromiseResolveBlock)resolve
                 setCompanyCertificatesRejecter:(RCTPromiseRejectBlock)reject)
{
    if( certificates == nil )
    {
        [Storage remove:[NSString stringWithFormat:@"%@/certificates.json", companyID]];
        resolve(@{ @"ok": [NSNumber numberWithBool:YES] });
        return;
    }
    else if( [certificates objectForKey:@"server"] == nil || [certificates objectForKey:@"key"] == nil || [certificates objectForKey:@"cert"] == nil || [certificates objectForKey:@"passphrase"] == nil )
    {
        reject(@"error", @"bad_arguments", nil);
    }
    
    NSString * passphrase = [[ExcaliburOpenSSL sha512With:[certificates objectForKey:@"passphrase"]] substringWithRange:NSMakeRange(0, 80)];
    NSString * pfx = [ExcaliburOpenSSL p12With:[certificates objectForKey:@"key"] cert:[certificates objectForKey:@"cert"] passphrase:passphrase];
    pfx = [[pfx componentsSeparatedByCharactersInSet:[NSCharacterSet newlineCharacterSet]] componentsJoinedByString:@""];
    NSDictionary * certs_dict = @{ @"server": [certificates objectForKey:@"server"], @"pfx": pfx, @"passphrase": passphrase };
    NSError * error;
    NSData * certs_data = [NSJSONSerialization dataWithJSONObject:certs_dict options:0 error:&error];
    
    if( !certs_data )
    {
        reject(@"error", @"not_saved", nil);
    }
    else
    {
        NSString * certs_json = [[NSString alloc] initWithData:certs_data encoding:NSUTF8StringEncoding];
        
        if( [Storage write:certs_json to:[NSString stringWithFormat:@"%@/certificates.json", companyID]] )
        {
            resolve(@{ @"ok": [NSNumber numberWithBool:YES] });
        }
        else
        {
            reject(@"error", @"not_saved", nil);
        }
    }
}

#pragma mark - Public actions

RCT_REMAP_METHOD(publicEncrypt,
                 public:(NSString *)public
                 data:(NSString *)data
                 format:(NSString *)format
                 publicEncryptResolver:(RCTPromiseResolveBlock)resolve
                 publicEncryptRejecter:(RCTPromiseRejectBlock)reject)
{
    NSString * encrypt = [ExcaliburOpenSSL publicEncryptWith:public data:data format:format];
    
    if( ![encrypt isEqualToString:@""] )
    {
        resolve(encrypt);
    }
    else
    {
        reject(@"error", @"bad_certificate", nil);
    }
}

RCT_REMAP_METHOD(aesEncrypt,
                 key:(NSString *)key
                 data:(NSString *)data
                 auth:(NSString *)auth
                 iv:(NSString *)iv
                 aesEncryptResolver:(RCTPromiseResolveBlock)resolve
                 aesEncryptRejecter:(RCTPromiseRejectBlock)reject)
{
    NSString * encrypt = [ExcaliburOpenSSL aesEncryptWith:key data:data auth:auth iv:iv];
    
    if( ![encrypt isEqualToString:@""] )
    {
        resolve(encrypt);
    }
    else
    {
        reject(@"error", @"bad_certificate", nil);
    }
}

RCT_REMAP_METHOD(aesDecrypt,
                 key:(NSString *)key
                 data:(NSString *)data
                 auth:(NSString *)auth
                 iv:(NSString *)iv
                 aesDecryptResolver:(RCTPromiseResolveBlock)resolve
                 aesDecryptRejecter:(RCTPromiseRejectBlock)reject)
{
    NSString * decrypt = [ExcaliburOpenSSL aesDecryptWith:key data:data auth:auth iv:iv];
    
    if( ![decrypt isEqualToString:@""] )
    {
        resolve(decrypt);
    }
    else
    {
        reject(@"error", @"bad_certificate", nil);
    }
}

RCT_REMAP_METHOD(sha256,
                 data:(NSString *)data
                 sha256Resolver:(RCTPromiseResolveBlock)resolve
                 sha256Rejecter:(RCTPromiseRejectBlock)reject)
{
    resolve([ExcaliburOpenSSL sha256With:data]);
}

RCT_REMAP_METHOD(getCertificates,
                 companyID:(NSString *)companyID
                 getcsrResolver:(RCTPromiseResolveBlock)resolve
                 getcsrRejecter:(RCTPromiseRejectBlock)reject)
{
    NSString * ca = @"-----BEGIN CERTIFICATE-----\n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\nsiYlaZh7ungNIY5HMT5+\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nMIIFoDCCA4igAwIBAgIBBTANBgkqhkiG9w0BAQsFADBgMQswCQYDVQQGEwJTSzEZ\nMBcGA1UECgwQRXhjYWxpYnVyIHMuci5vLjEaMBgGA1UECwwRRXhjYWxpYnVyIFJv\nb3QgQ0ExGjAYBgNVBAMMEUV4Y2FsaWJ1ciBSb290IENBMCAXDTE3MDkyNTEzMTMz\nMVoYDzIzMzMxMjMxMjM1OTU5WjBgMQswCQYDVQQGEwJTSzEZMBcGA1UECgwQRXhj\nYWxpYnVyIHMuci5vLjEaMBgGA1UECwwRRXhjYWxpYnVyIFJvb3QgQ0ExGjAYBgNV\nBAMMEUV4Y2FsaWJ1ciBSb290IENBMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIIC\nCgKCAgEAqUonlOX277jqyw6usNV8LQI0GnHOjH6ghEkm1Lvv97gTkg17/vCLlWxn\n7Z8sh6+PDjbicgJ9ERussjrwAvA2MCFNoAfSrHVb5y2qvp8HGIOLbPoMUgQs0L1E\ngggBD8S17YLxyiMpVc3WrClMNE62KXEP9g5OhnP8T0IIL+v+GMd6ha70xfp/RM7L\nWuv3nczJDRzt1gnXBXCcI+LaD/mUHSFPte8NdW2V6VC1p5L8UbvG2l0t3h7Zuw83\nqCAfHs224B6/Z6iJuvUDzIJ8EaQICS/OL2XRJAV90oRYJi60vcGN4SMwxDH5ZLHd\nhUy6spQ4GfYHnLbQ06lJ/6ErEwQvc3PktJS+v8WJVdkDIo0FqUbHV4nQvUwqN5b3\nD6ggJZ8fz3U04iYJsz5GA21sXAKIfLyHhlgvEVzSXSJtviOmJujrwur23wdPG9Ky\nff/5GO99UmP6c9HT0zFVGjpwG7EqMk2DGpdQxdJEE2rb2hn81WCLVpDdnLRCmyCC\nebknrn6Ln7+HkudACnFIaqiyAopEmNNEpyGaVoNfSWALqdaVCLq2lODL3L/jmkNR\nm/xmlV6NxOTdWW59+Nh807gZzZ6ZoxrjD2aPN5eKXQVLgrfZJ9iHGo/dvOei21Iv\nTklo3vi2jf0HzL3DXaXMD/whLwlYCK6eaHamcN3AskyJVvPlX5kCAwEAAaNjMGEw\nDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFIf0vdlB\nHTViMD8cllKhP+xYNG25MB8GA1UdIwQYMBaAFIf0vdlBHTViMD8cllKhP+xYNG25\nMA0GCSqGSIb3DQEBCwUAA4ICAQAYBLSg+5irZqHU6TRrM+GFHghF/JS828FpdiL6\nbpBkv3t6QDLUruSVABukiCQ5BorAu11aiU5amSMZ8cr6p43mZg2DTGfLd82rXUcC\nVlqmKuaMenahJrzGmpABtC7lHHzj/TiNoXHsjkYaI2meO5ZEgXJjLh18muIA8rkx\niZnqxF2t6kxIXAn1w5uKXJLmmIu8f8uy6OV9fnLNgEVrr5zKeoeaqwX2VVyxMTBu\naoXdMCo3mDK1vVx7mMZ9QK/pWQEJfUwEaJV+t7gLfIEQcPeqzzSjwO9OQzroGnmU\nehj4h0mPmWIUkmOrrBEhzx88xZew7iGItn9XfiWlT1H1LZmL+HDUj/gk3B7RprXg\nX+JVctWvCrtjoo2WWHR1YpFZ83/EjI3uOU2Y7wbgUT9IMkmIhsa1efGqXqZXsMX0\nmZZ1Y8Q9NoC7z332gNAbNHj5hUp44mrMBCCdQi3/1byAfgqLIx2PO229JBItL4fd\nystjyCyjiTO4D9ri+93+DT2FHy1OnDuBdAJZaREDZRgN7mVdKA0XhmqqcZWR1NFx\nsB5RvCne+ltng+7skEtQBd1x4jbO8A7Vbi19nioKERLF2OXacloNPSgaCa5qvbUm\nP55u+5aSk3+tm3xmni+88ck8mKw/gPffsJcrHdFiLO9kctEMCvzDy2CMKTTXSKJv\nGBrQaQ==\n-----END CERTIFICATE-----\n";
    NSString * passphrase = [[ExcaliburOpenSSL sha512With:@"ExcaliburEnterpriseToken"] substringWithRange:NSMakeRange(0, 80)];
    
    if( [Storage exists:[NSString stringWithFormat:@"%@/excalibur.pfx", companyID]] )
    {
        resolve(@{ @"ca": ca, @"pfx": [Storage read:[NSString stringWithFormat:@"%@/excalibur.pfx", companyID]], @"passphrase": passphrase });
    }
    else
    {
        NSString * pfx = @"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";
        
        resolve(@{ @"ca": ca, @"pfx": pfx, @"passphrase": passphrase });
    }
}

RCT_REMAP_METHOD(setCSRCertificate,
                 companyID:(NSString *)companyID
                 cert:(NSString *)cert
                 csrResolver:(RCTPromiseResolveBlock)resolve
                 csrRejecter:(RCTPromiseRejectBlock)reject)
{
    NSString * key = [Storage read:[NSString stringWithFormat:@"%@/excalibur.key", companyID]];
    NSString * passphrase = [[ExcaliburOpenSSL sha512With:@"ExcaliburEnterpriseToken"] substringWithRange:NSMakeRange(0, 80)];
    
    if( ![key isEqualToString:@""] )
    {
        NSString * pfx = [ExcaliburOpenSSL p12With:key cert:cert passphrase:passphrase];
        
        if( ![pfx isEqualToString:@""] )
        {
            if( [Storage write:pfx to:[NSString stringWithFormat:@"%@/excalibur.pfx", companyID]] )
            {
                [Storage remove:[NSString stringWithFormat:@"%@/excalibur.key", companyID]];
                
                resolve([NSNumber numberWithBool:YES]);
            }
            else
            {
                reject(@"error", @"cannot_save", nil);
            }
        }
        else
        {
            reject(@"error", @"cannot_generate_pfx", nil);
        }
    }
    else
    {
        reject(@"error", @"pem_not_exists", nil);
    }
}

RCT_REMAP_METHOD(generateCSR,
                 companyID:(NSString *)companyID
                 deviceID:(NSString *)deviceID
                 deviceType:(NSString *)deviceType
                 csrResolver:(RCTPromiseResolveBlock)resolve
                 csrRejecter:(RCTPromiseRejectBlock)reject)
{
    NSDictionary * csr = [ExcaliburOpenSSL generateCSR:companyID deviceID:deviceID deviceType:deviceType];
    
    if( [csr count] == 0 )
    {
        reject(@"error", @"cannot_generate", nil);
    }
    else
    {
        if( [Storage write:[csr objectForKey:@"key"] to:[NSString stringWithFormat:@"%@/excalibur.key", companyID]] )
        {
            resolve([csr objectForKey:@"CSR"]);
        }
        else
        {
            reject(@"error", @"cannot_save", nil);
        }
    }
}

@end
  
