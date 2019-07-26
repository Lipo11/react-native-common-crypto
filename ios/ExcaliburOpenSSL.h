#import <Foundation/Foundation.h>

@interface ExcaliburOpenSSL : NSObject

+ (NSString *)privateDecryptWith:(NSString *)key passphrase:(NSString *)passphrase data:(NSString *)data format:(NSString *)format;
+ (NSString *)privateEncryptWith:(NSString *)key passphrase:(NSString *)passphrase data:(NSString *)data format:(NSString *)format;
+ (NSString *)publicEncryptWith:(NSString *)cert data:(NSString *)data format:(NSString *)format;

+ (NSString *)aesEncryptWith:(NSString *)key data:(NSString *)data auth:(NSString *)auth iv:(NSString *)iv;
+ (NSString *)aesDecryptWith:(NSString *)key data:(NSString *)data auth:(NSString *)auth iv:(NSString *)iv;

+ (NSString *)p12With:(NSString *)key cert:(NSString *)cert passphrase:(NSString *)passphrase;

+ (NSString *)pbkdf2With:(NSString *)pass salt:(NSString *)salt iterations:(int)iterations;
+ (NSString *)sha256With:(NSString *)data;
+ (NSString *)sha512With:(NSString *)data;
+ (NSString *)hexToBase64With:(NSString *)data;

+ (NSDictionary *)generateCSR:(NSString *)companyID deviceID:(NSString *)deviceID deviceType:(NSString *)deviceType;

@end
