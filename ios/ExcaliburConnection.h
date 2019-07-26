#import <Foundation/Foundation.h>

@interface ExcaliburConnection : NSObject<NSURLConnectionDelegate>
{
    NSMutableData * _responseData;
}

@property (nonatomic, strong) NSDictionary * options;
@property (copy) void (^callback)(BOOL status, NSString * result);

- (instancetype)init;
- (void)startWithURL:(NSString *)url data:(NSString *)data options:(NSDictionary *)options callback:(void(^)(BOOL status, NSString * result))callback;

@end
