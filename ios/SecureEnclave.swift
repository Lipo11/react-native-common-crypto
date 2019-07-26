import Foundation
import Security
import LocalAuthentication

@objc(SecureEnclave)
class SecureEnclave: NSObject
{
    private var _currentContext : LAContext?
    
    static func requiresMainQueueSetup() -> Bool
    {
        return false
    }
    
    @objc(available:)
    func available( factor: String ) -> Bool
    {
        if( factor == "fingerprint" || factor == "biometry" )
        {
            let context = LAContext()
            var error: NSError?
            
            if( context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) )
            {
                return true
            }
            
            return false
        }
        else if( factor == "face" )
        {
            return false
        }
        
        return true
    }
    
    @objc(closeBiometrics)
    func closeBiometrics()
    {
        if #available(iOS 9.0, *)
        {
            _currentContext?.invalidate()
        }
    }
    
    @objc(generatePair:callback:)
    func generatePair( factor: String, callback: @escaping(( _ generated: Bool ) -> Void) )
    {
        DispatchQueue.global(qos: .background).async
        {
            var created : Bool = false
            let name : String = "excalibur-" + factor
            _ = self.deletePair(factor: factor)
            
            if( !self.existsPrivateCertificate(factor: factor) )
            {
                let requireBiometrics : Bool = ( factor == "fingerprint" || factor == "biometry" )
                let keyPairAttr = self.getGenerateParams(factor: factor, requireBiometrics: requireBiometrics)
                var publicKeyPtr, privateKeyPtr: SecKey?
                let result = SecKeyGeneratePair(keyPairAttr, &publicKeyPtr, &privateKeyPtr)
                
                if( result == errSecSuccess )
                {
                    if( self.forceSavePublicKey(publicKey: publicKeyPtr!, name: name) )
                    {
                        created = true
                    }
                }
            }
            
            DispatchQueue.main.async
            {
                callback(created)
            }
        }
    }
    
    @objc(getPublicKey:intent:data:text:callback:)
    func getPublicKey( factor: String, intent: String, data: String, text: String, callback: @escaping(( _ publicKey: String, _ signature: String, _ dataSignature: String ) -> Void) )
    {
        let name : String = "excalibur-" + factor
        let requireBiometrics : Bool = ( factor == "fingerprint" || factor == "biometry" )
        let keyPairAttr = getGenerateParams(factor: factor, requireBiometrics: requireBiometrics)
        
        DispatchQueue.global(qos: .background).async
        {
            if( !self.existsPrivateCertificate(factor: factor) )
            {
                var publicKeyPtr, privateKeyPtr: SecKey?
                let result = SecKeyGeneratePair(keyPairAttr, &publicKeyPtr, &privateKeyPtr)
                var created : Bool = false
                
                if( result == errSecSuccess )
                {
                    if( self.forceSavePublicKey(publicKey: publicKeyPtr!, name: name) )
                    {
                        created = true
                    }
                }
                
                if( !created )
                {
                    DispatchQueue.main.async
                    {
                        callback("", "creating_certs_failed", "")
                    }
                    
                    return
                }
            }
            
            let publicPem : String? = self.exportPublicKey(name: name)
            self.getPrivateKey(name: name, text: text, requireBiometrics: requireBiometrics, callback: {( privateKey: SecKey?, error: String ) in
                
                var publicKeyError : String = ( publicPem == nil ? "public_key_not_available" : error )
                
                if( publicPem != nil && privateKey != nil )
                {
                    let sign : Data? = self.signData(privateKey: privateKey!, plainText: intent.data(using: .utf8)!)
                    
                    if( sign != nil )
                    {
                        let publicKey : SecKey? = self.getPublicKey(name: name)
                        
                        if( publicKey != nil && self.verifyData(publicKey: publicKey!, signature: sign!, plainText: intent.data(using: .utf8)!) )
                        {
                            var dataSignature : String = "";
                            if( !data.isEmpty )
                            {
                                let dataSign : Data? = self.signData(privateKey: privateKey!, plainText: data.data(using: .utf8)!)
                                
                                if( dataSign != nil)
                                {
                                    dataSignature = dataSign!.base64EncodedString()
                                }
                            }
                            
                            DispatchQueue.main.async
                            {
                                callback(publicPem!, sign!.base64EncodedString(), dataSignature)
                            }
                            
                            return
                        }
                    }
                    
                    publicKeyError = "corrupted_data"
                }
                
                DispatchQueue.main.async
                {
                    _ = self.deletePair(factor: factor)
                    callback("", publicKeyError, "")
                }
            })
        }
    }
    
    @objc(sign:intent:data:text:callback:)
    func sign( factor: String, intent: String, data: String, text: String, callback: @escaping(( _ signature: String, _ dataSignature: String ) -> Void) )
    {
        if( intent.isEmpty ){ return callback("", "") }
        
        let name : String = "excalibur-" + factor
        let requireBiometrics : Bool = ( factor == "fingerprint" || factor == "biometry" )
        
        DispatchQueue.global(qos: .background).async
        {
            self.getPrivateKey(name: name, text: text, requireBiometrics: requireBiometrics, callback: {( privateKey: SecKey?, error: String ) in
                
                var signError: String = error
                
                if( privateKey != nil )
                {
                    let sign : Data? = self.signData(privateKey: privateKey!, plainText: intent.data(using: .utf8)!)
                    
                    if( sign != nil )
                    {
                        let publicKey : SecKey? = self.getPublicKey(name: name)
                        if( publicKey != nil && self.verifyData(publicKey: publicKey!, signature: sign!, plainText: intent.data(using: .utf8)!) )
                        {
                            var dataSignature : String = "";
                            if( !data.isEmpty )
                            {
                                let dataSign : Data? = self.signData(privateKey: privateKey!, plainText: data.data(using: .utf8)!)
                                
                                if( dataSign != nil)
                                {
                                    dataSignature = dataSign!.base64EncodedString()
                                }
                            }
                            
                            DispatchQueue.main.async
                            {
                                callback(sign!.base64EncodedString(), dataSignature)
                            }
                            
                            return
                        }
                    }
                    
                    signError = "corrupted_data"
                }
                
                DispatchQueue.main.async
                {
                    callback("", signError)
                }
                
            })
        }
    }
    
    @objc(existsPrivateCertificate:)
    func existsPrivateCertificate( factor: String ) -> Bool
    {
        let name : String = "excalibur-" + factor
        let parameters = [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecAttrLabel as String: name,
            kSecReturnRef as String: true
        ] as CFDictionary
        
        let status = SecItemCopyMatching(parameters, nil)
        
        return ( status == errSecSuccess )
    }
    
    private func getGenerateParams( factor: String, requireBiometrics: Bool ) -> NSDictionary
    {
        let name : String = "excalibur-" + factor
        
        if #available(iOS 9.0, *)
        {
            let context = LAContext()
            var error: NSError?
            
            if( context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) )
            {
                let access = SecAccessControlCreateWithFlags(kCFAllocatorDefault, ( factor == "location" ? kSecAttrAccessibleAlwaysThisDeviceOnly : kSecAttrAccessibleWhenUnlockedThisDeviceOnly ), ( requireBiometrics ? [ .privateKeyUsage, .touchIDCurrentSet ] : [ .privateKeyUsage ] ), nil)
                let privateKeyAttr = [ kSecAttrLabel as String: name, kSecAttrIsPermanent as String : true, kSecAttrAccessControl as String : access!, kSecUseOperationPrompt as String : "factor_fingerprint_message_touch_sensor" ] as NSDictionary
                
                return [
                    kSecAttrTokenID as String : kSecAttrTokenIDSecureEnclave,
                    kSecAttrKeyType as String : kSecAttrKeyTypeEC,
                    kSecAttrKeySizeInBits as String : 256,
                    kSecPrivateKeyAttrs as String : privateKeyAttr
                ] as NSDictionary
            }
        }
        
        let access = SecAccessControlCreateWithFlags(kCFAllocatorDefault, ( factor == "location" ? kSecAttrAccessibleAlwaysThisDeviceOnly : kSecAttrAccessibleWhenUnlockedThisDeviceOnly ), [], nil)
        let privateKeyAttr = [ kSecAttrLabel as String: name, kSecAttrIsPermanent as String : true, kSecAttrAccessControl as String : access! ] as NSDictionary
        
        return [
            kSecAttrKeyType as String : kSecAttrKeyTypeEC,
            kSecAttrKeySizeInBits as String : 256,
            kSecPrivateKeyAttrs as String : privateKeyAttr
        ] as NSDictionary
    }
    
    private func signData( privateKey: SecKey, plainText: Data ) -> Data?
    {
        let digestToSign = self.sha256Digest(forData: plainText)
        
        var digestToSignBytes = [UInt8](repeating: 0, count: digestToSign.count)
        digestToSign.copyBytes(to: &digestToSignBytes, count: digestToSign.count)
        
        var signatureBytes = [UInt8](repeating: 0, count: 128)
        var signatureLength = 128
        
        let signErr = SecKeyRawSign(privateKey, .PKCS1, &digestToSignBytes, digestToSignBytes.count, &signatureBytes, &signatureLength)
        if( signErr != errSecSuccess )
        {
            return nil
        }
        
        let signature = Data(bytes: &signatureBytes, count: signatureLength)
        return signature
    }
    
    private func verifyData( publicKey: SecKey, signature: Data, plainText: Data ) -> Bool
    {
        let sha = self.sha256Digest(forData: plainText)
        var shaBytes = [UInt8](repeating: 0, count: sha.count)
        sha.copyBytes(to: &shaBytes, count: sha.count)
        
        var signatureBytes = [UInt8](repeating: 0, count: signature.count)
        signature.copyBytes(to: &signatureBytes, count: signature.count)
        
        let status = SecKeyRawVerify(publicKey, .PKCS1, &shaBytes, shaBytes.count, &signatureBytes, signatureBytes.count)
        return ( status == errSecSuccess )
    }
    
    private func sha256Digest(forData data : Data) -> Data
    {
        let len = Int(CC_SHA256_DIGEST_LENGTH)
        let digest = UnsafeMutablePointer<UInt8>.allocate(capacity: len)
        CC_SHA256((data as NSData).bytes, CC_LONG(data.count), digest)
        return NSData(bytesNoCopy: UnsafeMutableRawPointer(digest), length: len) as Data
    }
    
    @objc(deletePair:)
    func deletePair( factor: String ) -> Bool
    {
        let name : String = "excalibur-" + factor
        var parameters = [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyType as String: kSecAttrKeyTypeEC,
            kSecAttrApplicationTag as String: "public-" + name,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic
        ] as CFDictionary
        
        SecItemDelete(parameters)
        
        parameters = [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyType as String: kSecAttrKeyTypeEC,
            kSecAttrLabel as String: name,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate
        ] as CFDictionary
        
        SecItemDelete(parameters)
        
        return true
    }
    
    private func forceSavePublicKey( publicKey: SecKey, name: String ) -> Bool
    {
        let parameters = [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyType as String: kSecAttrKeyTypeEC,
            kSecAttrApplicationTag as String: "public-" + name,
            kSecValueRef as String: publicKey,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic
            ] as CFDictionary
        
        SecItemDelete(parameters)
        
        var data : AnyObject?
        let status = SecItemAdd(parameters, &data)
        
        return ( status == errSecSuccess )
    }
    
    private func exportPublicKey( name: String ) -> String?
    {
        var matchResult: AnyObject? = nil
        
        let query: [String:Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyType as String: kSecAttrKeyTypeEC,
            kSecAttrApplicationTag as String: "public-" + name,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
            kSecReturnData as String: true
        ]
        
        let status = SecItemCopyMatching(query as CFDictionary, &matchResult)
        
        if( status == errSecSuccess )
        {
            return SecureEnclaveExport(matchResult as! Data).PEM
        }
        
        return nil
    }
    
    private func getPublicKey( name: String ) -> SecKey?
    {
        var raw: CFTypeRef?
        
        let query: [String:Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyType as String: kSecAttrKeyTypeEC,
            kSecAttrApplicationTag as String: "public-" + name,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
            kSecReturnRef as String: true
        ]
        
        let status = SecItemCopyMatching(query as CFDictionary, &raw)
        
        if( status == errSecSuccess )
        {
            return raw as! SecKey?
        }
        
        return nil
    }
    
    private func getPrivateKey( name: String, text: String, requireBiometrics: Bool, callback: @escaping(( _ privateKey: SecKey?, _ error: String ) -> Void) )
    {
        if( !requireBiometrics )
        {
            let parameters = [
                kSecClass as String: kSecClassKey,
                kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
                kSecAttrLabel as String: name,
                kSecReturnRef as String: true
            ] as CFDictionary
            
            var raw: CFTypeRef?
            let status = SecItemCopyMatching(parameters, &raw)
            
            if( status == errSecSuccess )
            {
                callback(raw as! SecKey?, "")
            }
            else
            {
                callback(nil, "missing_cert")
            }
        }
        else if #available(iOS 9.0, *)
        {
            _currentContext = LAContext()
            var error : NSError?
            
            guard _currentContext!.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) else
            {
                return callback(nil, "biometrics_failed")
            }
            
            if let domainState = _currentContext!.evaluatedPolicyDomainState
            {
                let bData = domainState.base64EncodedData()
                if let currentState = String(data: bData, encoding: .utf8)
                {
                    let savedState = UserDefaults.standard.string(forKey: "biometry_state")
                    UserDefaults.standard.set(currentState, forKey: "biometry_state")
                    
                    if( savedState != nil )
                    {
                        if( currentState != savedState )
                        {
                            return callback(nil, "biometry_changed")
                        }
                    }
                }
            }
            
            _currentContext!.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: text, reply: {(success, error) in
                
                if( success )
                {
                    let parameters = [
                        kSecClass as String: kSecClassKey,
                        kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
                        kSecAttrLabel as String: name,
                        kSecUseAuthenticationUI as String: kSecUseAuthenticationUIAllow,
                        kSecUseAuthenticationContext as String: self._currentContext!,
                        kSecReturnRef as String: true
                    ] as CFDictionary
                    
                    var raw: CFTypeRef?
                    let status = SecItemCopyMatching(parameters, &raw)
                    
                    if( status == errSecSuccess )
                    {
                        self._currentContext = nil
                        return callback(raw as! SecKey?, "")
                    }
                    else
                    {
                        callback(nil, "missing_cert")
                    }
                }
                else
                {
                    let authError: LAError = error as! LAError
                    
                    //print("-----=====------", self.error4Biometrics(authError: authError))
                    
                    callback(nil, ( authError.code == LAError.userCancel ? "canceled" : "biometrics_failed" ))
                }
                
            })
        }
        else{ callback(nil, "biometrics_failed") }
    }
    
    private func error4Biometrics( authError: LAError ) -> String
    {
        var error = ""
        
        if( authError.code == LAError.authenticationFailed ){ error = "authentication_failed" }
        else if( authError.code == LAError.passcodeNotSet ){ error = "passcode_not_set" }
        else if( authError.code == LAError.systemCancel ){ error = "system_cancel" }
        else if( authError.code == LAError.touchIDNotAvailable ){ error = "biometry_not_available" }
        else if( authError.code == LAError.touchIDNotEnrolled ){ error = "biometry_not_enrolled" }
        else if( authError.code == LAError.userCancel ){ error = "user_cancel" }
        else if( authError.code == LAError.userFallback ){ error = "user_fallback" }
        else if( authError.code == LAError.notInteractive ){ error = "not_interactive" }
        
        if #available(iOS 9.0, *)
        {
            if( error == "" )
            {
                if( authError.code == LAError.appCancel ){ error = "app_cancel" }
                else if( authError.code == LAError.invalidContext ){ error = "invalid_context" }
                else if( authError.code == LAError.touchIDLockout ){ error = "biometry_lockout" }
            }
        }
        
        if #available(iOS 11.0, *)
        {
            if( error == "" )
            {
                if( authError.code == LAError.biometryNotAvailable ){ error = "biometry_not_available" }
                else if( authError.code == LAError.biometryNotEnrolled ){ error = "biometry_not_enrolled" }
                else if( authError.code == LAError.biometryLockout ){ error = "biometry_lockout" }
            }
        }
        
        return error
    }
}

public struct SecureEnclaveConstants
{
    static var x9_62Header: Data = Data(bytes: [UInt8]([0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00]))
}

public final class SecureEnclaveExport
{
    let raw: Data
    
    lazy var DER: Data =
        {
            var result = SecureEnclaveConstants.x9_62Header
            result.append(self.raw)
            return result
    }()
    
    lazy var PEM: String =
    {
        var lines = String()
        lines.append("-----BEGIN PUBLIC KEY-----\n")
        lines.append(self.DER.base64EncodedString(options: [.lineLength64Characters, .endLineWithCarriageReturn]))
        lines.append("\n-----END PUBLIC KEY-----")
        return lines
    }()
    
    fileprivate init(_ raw: Data)
    {
        self.raw = raw
    }
}
