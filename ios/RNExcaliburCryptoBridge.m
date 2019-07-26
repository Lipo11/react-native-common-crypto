#import <React/RCTBridgeModule.h>

@interface RCT_EXTERN_MODULE(SecureEnclave, NSObject)

RCT_EXTERN_METHOD(hasSecureEnclave:(NSString *)factor)
RCT_EXTERN_METHOD(available:(NSString *)factor)
RCT_EXTERN_METHOD(closeBiometrics)
RCT_EXTERN_METHOD(generatePair:(NSString *)factor callback:(void(^)(BOOL generated))callback)
RCT_EXTERN_METHOD(getPublicKey:(NSString *)factor intent:(NSString *)intent data:(NSString *)data text:(NSString *)text callback:(void(^)(NSString * publicKey, NSString * signature, NSString * dataSignature))callback)
RCT_EXTERN_METHOD(sign:(NSString *)factor intent:(NSString *)intent data:(NSString *)data text:(NSString *)text callback:(void(^)(NSString * signature, NSString * dataSignature))callback)
RCT_EXTERN_METHOD(deletePair:(NSString *)factor)

@end
