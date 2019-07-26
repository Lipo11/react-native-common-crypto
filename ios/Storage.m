#import "Storage.h"
#import <CommonCrypto/CommonCryptor.h>
#import <CommonCrypto/CommonDigest.h>

@implementation Storage

static NSString * s_password = @"";
static NSString * s_iv = @"F68A9A229A516752";

+ (NSString *)getPassword
{
    if( [s_password isEqualToString:@""] )
    {
        s_password = [[UIDevice currentDevice] identifierForVendor].UUIDString;
    }
    
    return s_password;
}

+ (NSString *)applicationDocumentsDirectory
{
    return [[[NSFileManager defaultManager] URLsForDirectory:NSDocumentDirectory inDomains:NSUserDomainMask] lastObject].path;
}

+ (NSString *)getFullPath:(NSString *)path
{
    return [NSString stringWithFormat:@"%@/Excalibur/%@", [Storage applicationDocumentsDirectory], path];
}

+ (BOOL)exists:(NSString *)path
{
    return [[NSFileManager defaultManager] fileExistsAtPath:[Storage getFullPath:path]];
}

+ (BOOL)write:(NSString *)data to:(NSString *)path
{
    NSData * encodedData = [Storage AES128EncryptedDataWithKey:[Storage getPassword] data:[data dataUsingEncoding:NSUTF8StringEncoding]];
    NSString * encodedString = [encodedData base64EncodedStringWithOptions:kNilOptions];
    
    NSFileManager * NSFM = [NSFileManager defaultManager];
    NSString * fullPath = [Storage getFullPath:path];
    NSString * fullDirectory = [fullPath stringByDeletingLastPathComponent];
    
    if( ![NSFM fileExistsAtPath:fullDirectory] ){ [NSFM createDirectoryAtPath:fullDirectory withIntermediateDirectories:YES attributes:nil error:nil]; }
    
    return [NSFM createFileAtPath:fullPath contents:nil attributes:nil] && [encodedString writeToFile:fullPath atomically:YES encoding:NSUTF8StringEncoding error:nil];
}

+ (NSString *)read:(NSString *)path
{
    NSString * fullPath = [Storage getFullPath:path];
    NSString * encodedFile = [NSString stringWithContentsOfFile:fullPath usedEncoding:nil error:nil];
    
    if( encodedFile != nil && ![encodedFile isEqualToString:@""] )
    {
        NSData * encodedData = [[NSData alloc] initWithBase64EncodedString:encodedFile options:kNilOptions];
        
        if( encodedData != nil )
        {
            NSString * decodedString = [[NSString alloc] initWithData:[Storage AES128DecryptedDataWithKey:[Storage getPassword] data:encodedData] encoding:NSUTF8StringEncoding];
            
            if( decodedString != nil )
            {
                return decodedString;
            }
        }
    }
    
    return @"";
}

+ (BOOL)remove:(NSString *)path
{
    NSString * fullPath = [Storage getFullPath:path];
    
    return [[NSFileManager defaultManager] removeItemAtPath:fullPath error:nil];
}

+ (BOOL)removeAll
{
    return [[NSFileManager defaultManager] removeItemAtPath:[NSString stringWithFormat:@"%@/Excalibur/", [Storage applicationDocumentsDirectory]] error:nil];
}

+ (NSString*)sha256:(NSString *)data
{
    const char * str = [data UTF8String];
    unsigned char result[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(str, (unsigned int)strlen(str), result);
    
    NSMutableString * ret = [NSMutableString stringWithCapacity:CC_SHA256_DIGEST_LENGTH*2];
    for( int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++ )
    {
        [ret appendFormat:@"%02x",result[i]];
    }
    
    return ret;
}

+ (NSData *)AES128EncryptedDataWithKey:(NSString *)key data:(NSData *)data
{
    return [Storage AES128Operation:kCCEncrypt key:key data:data iv:s_iv];
}

+ (NSData *)AES128DecryptedDataWithKey:(NSString *)key data:(NSData *)data
{
    return [Storage AES128Operation:kCCDecrypt key:key data:data iv:s_iv];
}

+ (NSData *)AES128Operation:(CCOperation)operation key:(NSString *)key data:(NSData *)data iv:(NSString *)iv
{
    key = [Storage sha256:key];
    
    char keyPtr[kCCKeySizeAES128 + 1];
    bzero(keyPtr, sizeof(keyPtr));
    [key getCString:keyPtr maxLength:sizeof(keyPtr) encoding:NSUTF8StringEncoding];
    
    char ivPtr[kCCBlockSizeAES128 + 1];
    bzero(ivPtr, sizeof(ivPtr));
    if( iv )
    {
        [iv getCString:ivPtr maxLength:sizeof(ivPtr) encoding:NSUTF8StringEncoding];
    }
    
    NSUInteger dataLength = [data length];
    size_t bufferSize = dataLength + kCCBlockSizeAES128;
    void *buffer = malloc(bufferSize);
    
    size_t numBytesEncrypted = 0;
    CCCryptorStatus cryptStatus = CCCrypt(operation,
                                          kCCAlgorithmAES128,
                                          kCCOptionPKCS7Padding | kCCOptionECBMode,
                                          keyPtr,
                                          kCCBlockSizeAES128,
                                          ivPtr,
                                          [data bytes],
                                          dataLength,
                                          buffer,
                                          bufferSize,
                                          &numBytesEncrypted);
    if( cryptStatus == kCCSuccess )
    {
        return [NSData dataWithBytesNoCopy:buffer length:numBytesEncrypted];
    }
    
    free(buffer);
    return nil;
}

@end
