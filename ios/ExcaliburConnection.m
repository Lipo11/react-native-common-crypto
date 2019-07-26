#import "ExcaliburConnection.h"

@implementation ExcaliburConnection

- (instancetype)init
{
    self = [super init];
    
    if( self )
    {
        
    }
    
    return self;
}

- (void)startWithURL:(NSString *)url data:(NSString *)data options:(NSDictionary *)options callback:(void(^)(BOOL status, NSString * result))callback
{
    self.options = options;
    self.callback = callback;
    
    NSMutableURLRequest * request = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:url]];
    request.HTTPMethod = @"GET";
    [request setValue:@"application/json; charset=utf-8" forHTTPHeaderField:@"Content-Type"];
    NSData * requestBodyData = [data dataUsingEncoding:NSUTF8StringEncoding];
    request.HTTPBody = requestBodyData;
    
    NSURLConnection * connection = [[NSURLConnection alloc] initWithRequest:request delegate:self startImmediately:NO];
    [connection scheduleInRunLoop:[NSRunLoop mainRunLoop] forMode:NSDefaultRunLoopMode];
    
    [connection start];
}

#pragma mark NSURLConnection Delegate Methods

- (void)connection:(NSURLConnection *)connection didReceiveResponse:(NSURLResponse *)response
{
    _responseData = [[NSMutableData alloc] init];
}

- (void)connection:(NSURLConnection *)connection didReceiveData:(NSData *)data
{
    [_responseData appendData:data];
}

- (NSCachedURLResponse *)connection:(NSURLConnection *)connection willCacheResponse:(NSCachedURLResponse*)cachedResponse
{
    return nil;
}

- (void)connectionDidFinishLoading:(NSURLConnection *)connection
{
    NSString * responseString = [[NSString alloc] initWithData:_responseData encoding:NSUTF8StringEncoding];
    _responseData = nil;
    
    self.callback(YES, responseString);
}

- (void)connection:(NSURLConnection *)connection didFailWithError:(NSError *)error
{
    self.callback(NO, error.description);
}

- (void)connection:(NSURLConnection *)connection willSendRequestForAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge
{
    if( challenge.proposedCredential && !challenge.error )
    {
        [challenge.sender useCredential:challenge.proposedCredential forAuthenticationChallenge:challenge];
        
        return;
    }
    
    NSString * strAuthenticationMethod = challenge.protectionSpace.authenticationMethod;
    
    NSURLCredential * credential = nil;
    if( [strAuthenticationMethod isEqualToString:NSURLAuthenticationMethodClientCertificate] )
    {
        NSData * PKCS12Data = [[NSData alloc] initWithBase64EncodedString:[self.options objectForKey:@"pfx"] options:0];
        
        NSDictionary * optionsDictionary = [NSDictionary dictionaryWithObject:[self.options objectForKey:@"passphrase"] forKey:(__bridge id)kSecImportExportPassphrase];
        CFArrayRef items = CFArrayCreate(NULL, 0, 0, NULL);
        OSStatus securityError = SecPKCS12Import((__bridge CFDataRef)PKCS12Data,(__bridge CFDictionaryRef)optionsDictionary, &items);
        
        SecIdentityRef identity = NULL;
        SecCertificateRef certificate = NULL;
        
        if( securityError == errSecSuccess )
        {
            CFDictionaryRef myIdentityAndTrust = CFArrayGetValueAtIndex(items, 0);
            identity = (SecIdentityRef)CFDictionaryGetValue (myIdentityAndTrust, kSecImportItemIdentity);
            
            CFArrayRef array = (CFArrayRef)CFDictionaryGetValue(myIdentityAndTrust, kSecImportItemCertChain);
            certificate = (SecCertificateRef)CFArrayGetValueAtIndex(array, 0);
        }
        
        credential = [NSURLCredential credentialWithIdentity:identity certificates:[NSArray arrayWithObject:(__bridge id)(certificate)] persistence:NSURLCredentialPersistenceNone];
        
        CFRelease(items);
    }
    else if( [strAuthenticationMethod isEqualToString:NSURLAuthenticationMethodServerTrust] )
    {
        int trustCertificateCount = (int)SecTrustGetCertificateCount(challenge.protectionSpace.serverTrust);
        NSMutableArray * trustCertificates = [[NSMutableArray alloc] initWithCapacity:trustCertificateCount];
        for( int i = 0; i < trustCertificateCount; i++ )
        {
            SecCertificateRef trustCertificate =  SecTrustGetCertificateAtIndex(challenge.protectionSpace.serverTrust, i);
            [trustCertificates addObject:(__bridge id) trustCertificate];
        }
        
        SecPolicyRef policyRef = NULL;
        policyRef = SecPolicyCreateSSL(YES, (__bridge CFStringRef) challenge.protectionSpace.host);
        
        SecTrustRef trustRef = NULL;
        if( policyRef )
        {
            SecTrustCreateWithCertificates((__bridge CFArrayRef) trustCertificates, policyRef, &trustRef);
            CFRelease(policyRef);
        }
        
        if( trustRef )
        {
            //          SecTrustSetAnchorCertificates(trustRef, (__bridge CFArrayRef) [NSArray array]);
            //          SecTrustSetAnchorCertificatesOnly(trustRef, NO);
            
            SecTrustResultType result;
            OSStatus trustEvalStatus = SecTrustEvaluate(trustRef, &result);
            if( trustEvalStatus == errSecSuccess )
            {
                // just temporary attempt to make it working.
                // i hope, there is no such problem, when we have final working version of certificates.
                if( result == kSecTrustResultRecoverableTrustFailure )
                {
                    CFDataRef errDataRef = SecTrustCopyExceptions(trustRef);
                    SecTrustSetExceptions(trustRef, errDataRef);
                    
                    SecTrustEvaluate(trustRef, &result);
                }
                
                if( result == kSecTrustResultProceed || result == kSecTrustResultUnspecified )
                {
                    credential = [NSURLCredential credentialForTrust:trustRef];
                }
            }
            
            CFRelease(trustRef);
        }
    }
    else
    {
        NSLog(@"Unexpected authentication method. Cancelling authentication ...");
        [challenge.sender cancelAuthenticationChallenge:challenge];
    }
    
    if( credential )
    {
        [challenge.sender useCredential:credential forAuthenticationChallenge:challenge];
    }
    else
    {
        [challenge.sender cancelAuthenticationChallenge:challenge];
    }
}

@end
