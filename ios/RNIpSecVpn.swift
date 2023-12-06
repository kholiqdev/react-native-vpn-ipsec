//
//  RNIpSecVpn.swift
//  RNIpSecVpn
//
//  Created by Sina Javaheri on 25/02/1399.
//  Copyright © 1399 AP Sijav. All rights reserved.
//

import Foundation
import NetworkExtension
import Security
import KeychainAccess



public struct KeychainWrapper {
    
    public static var instance: Keychain {
        return Keychain(service: Bundle.main.bundleIdentifier  ?? "org.keychain.rnvpn")
    }

    public static func setPassword(_ password: String, forVPNID VPNID: String) {
        let key = NSURL(string: VPNID)!.lastPathComponent!
        _ = try? instance.remove(key)
        instance[key] = password
    }
    
    public static func setSecret(_ secret: String, forVPNID VPNID: String) {
        let key = NSURL(string: VPNID)!.lastPathComponent!
        _ = try? instance.remove("\(key)psk")
        instance["\(key)psk"] = secret
    }
    
    public static func passwordRefForVPNID(_ VPNID: String) -> Data? {
        let key = NSURL(string: VPNID)!.lastPathComponent!
        return instance[attributes: key]?.persistentRef
    }
    
    public static func secretRefForVPNID(_ VPNID: String) -> Data? {
        let key = NSURL(string: VPNID)!.lastPathComponent!
        if let data = instance[attributes: "\(key)psk"]?.data, let value = String(data: data, encoding: .utf8) {
            if !value.isEmpty {
                return instance[attributes: "\(key)psk"]?.persistentRef
            }
        }
        return nil
    }
    

    public static func setCertificate(_ secret: String, forVPNID VPNID: String) {
        let key = NSURL(string: VPNID)!.lastPathComponent!
        _ = try? instance.remove("\(key)cert")
        instance["\(key)cert"] = secret
    }

    public static func certificateRefForVPNID(_ VPNID: String) -> Data? {
        let key = NSURL(string: VPNID)!.lastPathComponent!
        if let data = instance[attributes: "\(key)cert"]?.data, let value = String(data: data, encoding: .utf8) {
            if !value.isEmpty {
                return instance[attributes: "\(key)cert"]?.persistentRef
            }
        }
        return nil
    }
    
    
    
    
    
    
    
    public static func destoryKeyForVPNID(_ VPNID: String) {
        let key = NSURL(string: VPNID)!.lastPathComponent!
        _ = try? instance.remove(key)
        _ = try? instance.remove("\(key)psk")
        _ = try? instance.remove("\(key)cert")
    }
    
    public static func passwordStringForVPNID(_ VPNID: String) -> String? {
        let key = NSURL(string: VPNID)!.lastPathComponent!
        return instance[key]
    }
    
    public static func secretStringForVPNID(_ VPNID: String) -> String? {
        let key = NSURL(string: VPNID)!.lastPathComponent!
        return instance["\(key)psk"]
    }

}



@objc(RNIpSecVpn)
class RNIpSecVpn: RCTEventEmitter {
    
    @objc let vpnManager = NEVPNManager.shared();
    @objc let defaultErr = NSError()
    
    override static func requiresMainQueueSetup() -> Bool {
        return false
    }
    
    override func supportedEvents() -> [String]! {
        return [ "stateChanged" ]
    }
    
    @objc
    func prepare(_ findEventsWithResolver: RCTPromiseResolveBlock, rejecter: RCTPromiseRejectBlock) -> Void {
        
        self.vpnManager.loadFromPreferences { (error) in
            if error != nil {
                print(error.debugDescription)
            }
            else{
                print("No error from loading VPN viewDidLoad")
            }

                                               
            if self?.vpnManager.connection.status == .invalid{
                let p = NEVPNProtocolIPSec()
                p.username = "vpn"
                p.serverAddress = "127.0.0.1"
                p.authenticationMethod = .sharedSecret
                p.useExtendedAuthentication = true
                self?.vpnManager.protocolConfiguration  = p
                self?.vpnManager.isEnabled = true
                self?.vpnManager.localizedDescription = "vpn"
                
                self?.vpnManager.saveToPreferences { error in
                    if let err = error {
                        print("Failed to save profile: \(err.localizedDescription)")
                    } else {
                    
                    }
                }
                
            }
        }

        // Register to be notified of changes in the status. These notifications only work when app is in foreground.
        NotificationCenter.default.addObserver(forName: NSNotification.Name.NEVPNStatusDidChange, object : nil , queue: nil) {
            notification in
            let nevpnconn = notification.object as! NEVPNConnection
            self.sendEvent(withName: "stateChanged", body: [ "state" : checkNEStatus(status: nevpnconn.status) ])
        }
        
        findEventsWithResolver(nil)
    }
    
    
    
    @objc
    func connect(_ config: NSDictionary, address: NSString, username: NSString, password: NSString, secret: NSString, disconnectOnSleep: Bool=false, findEventsWithResolver: @escaping RCTPromiseResolveBlock, rejecter: @escaping RCTPromiseRejectBlock )->Void{
        
        loadReference(config, address: address, username: username, password: password,  secret: secret, disconnectOnSleep: disconnectOnSleep, findEventsWithResolver: findEventsWithResolver, rejecter: rejecter, isPrepare: false)
    }
    
    @objc
    func saveConfig(_ config: NSDictionary, address: NSString, username: NSString, password: NSString,  secret: NSString, findEventsWithResolver: @escaping RCTPromiseResolveBlock, rejecter: @escaping RCTPromiseRejectBlock )->Void{
        
        loadReference(config, address: address, username: username, password: password,   secret: secret, disconnectOnSleep: false, findEventsWithResolver: findEventsWithResolver, rejecter: rejecter, isPrepare: true)
    }
    
    @objc
    func loadReference(_ config: NSDictionary, address: NSString, username: NSString, password: NSString,  secret: NSString, disconnectOnSleep: Bool, findEventsWithResolver: @escaping RCTPromiseResolveBlock, rejecter: @escaping RCTPromiseRejectBlock,isPrepare:Bool) -> Void {
        
        if !isPrepare{
            self.sendEvent(withName: "stateChanged", body: [ "state" : 1 ])
        }
        self.vpnManager.loadFromPreferences { (error) -> Void in
            
            if error != nil {
                print("VPN Preferences error: 1")
            } else {
                if let type = config["type"] as? String{
                    if "ipsec" == type{
                        let p = NEVPNProtocolIPSec()
                        p.username = username as String
                        p.serverAddress = address as String
                        if let authenticationMethod  = config["authenticationMethod"] as? NSInteger {
                            p.authenticationMethod  = NEVPNIKEAuthenticationMethod.init(rawValue: authenticationMethod) ?? .none
                        }
                        else{
                            p.authenticationMethod = NEVPNIKEAuthenticationMethod.none
                        }
                        
                        if let cert = config["cert"] as? String,cert.count>0{
                            let identityData = cert.data(using: .utf8)
                            p.identityData = identityData
                        }
                        
                        
                        KeychainWrapper.setSecret(secret as String, forVPNID: "secret")
                        KeychainWrapper.setPassword(password as String, forVPNID: "password")

                        
                        p.sharedSecretReference = KeychainWrapper.secretRefForVPNID("secret")
                        p.passwordReference = KeychainWrapper.passwordRefForVPNID("password")
                        
               
                        
                        p.useExtendedAuthentication = true
                        p.disconnectOnSleep = disconnectOnSleep
                        
                        self.vpnManager.protocolConfiguration = p
                    }
                    else if "ikev2" == type{
                        let p = NEVPNProtocolIKEv2()
                        
                        p.username = username as String
                        p.serverAddress = address as String
                        if let authenticationMethod  = config["authenticationMethod"] as? NSInteger {
                            p.authenticationMethod  = NEVPNIKEAuthenticationMethod.init(rawValue: authenticationMethod) ?? .none
                            
                        }
                        else{
                            p.authenticationMethod = NEVPNIKEAuthenticationMethod.none
                        }
                        if let cert = config["cert"] as? String,cert.count>0{
                            let identityData = cert.data(using: .utf8)
                            p.identityData = identityData
                        }
                        
                        if password.length > 0 {
                            KeychainWrapper.setPassword(password as String, forVPNID: "password")
                            p.passwordReference = KeychainWrapper.passwordRefForVPNID("password")
                        }
                        if secret.length > 0{
                            KeychainWrapper.setSecret(secret as String, forVPNID: "secret")
                            p.sharedSecretReference = KeychainWrapper.secretRefForVPNID("secret")
                        }
                        
                        if let remoteIdentifier = config.value(forKey: "remoteIdentifier") as? String{
                            p.remoteIdentifier = remoteIdentifier
                        }
                        if let localIdentifier = config.value(forKey: "localIdentifier") as? String{
                            p.localIdentifier = localIdentifier
                        }
                        
                        if let certificateType = config.value(forKey: "certificateType") as? Int{
                            p.certificateType = .init(rawValue: certificateType) ?? .RSA
                        }
                        
                        if let identityData = config.value(forKey: "identityData") as? String,identityData.count > 0{
                            p.identityData = identityData.data(using: .utf8)
                        }
                        
                        if let ikeSecurityAssociationParameters = config.value(forKey: "ikeSecurityAssociationParameters") as? NSDictionary ,
                           let encryptionAlgorithm = ikeSecurityAssociationParameters["encryptionAlgorithm"] as? Int,
                           let integrityAlgorithm = ikeSecurityAssociationParameters["integrityAlgorithm"] as? Int,
                           let diffieHellmanGroup = ikeSecurityAssociationParameters["diffieHellmanGroup"] as? Int,
                           let lifetimeMinutes = ikeSecurityAssociationParameters["lifetimeMinutes"] as? Int{
                            
                            p.ikeSecurityAssociationParameters.encryptionAlgorithm = .init(rawValue: encryptionAlgorithm) ?? .algorithmAES256
                            
                            p.ikeSecurityAssociationParameters.integrityAlgorithm  = .init(rawValue: integrityAlgorithm) ?? .SHA256
                            
                            p.ikeSecurityAssociationParameters.diffieHellmanGroup  = .init(rawValue: diffieHellmanGroup) ?? .group14
                            
                            p.ikeSecurityAssociationParameters.lifetimeMinutes  = Int32(lifetimeMinutes)

                            
                        }
                        
                        if let childSecurityAssociationParameters = config.value(forKey: "childSecurityAssociationParameters") as? NSDictionary ,
                           let encryptionAlgorithm = childSecurityAssociationParameters["encryptionAlgorithm"] as? Int,
                           let integrityAlgorithm = childSecurityAssociationParameters["integrityAlgorithm"] as? Int,
                           let diffieHellmanGroup = childSecurityAssociationParameters["diffieHellmanGroup"] as? Int,
                           let lifetimeMinutes = childSecurityAssociationParameters["lifetimeMinutes"] as? Int{
                            
                            p.childSecurityAssociationParameters.encryptionAlgorithm = .init(rawValue: encryptionAlgorithm) ?? .algorithmAES256
                            
                            p.childSecurityAssociationParameters.integrityAlgorithm  = .init(rawValue: integrityAlgorithm) ?? .SHA256
                            
                            p.childSecurityAssociationParameters.diffieHellmanGroup  = .init(rawValue: diffieHellmanGroup) ?? .group14
                            
                            p.childSecurityAssociationParameters.lifetimeMinutes  = Int32(lifetimeMinutes)

                            
                        }

                        p.useExtendedAuthentication = true
                        p.disconnectOnSleep = disconnectOnSleep
                        self.vpnManager.protocolConfiguration = p
                        
                    }
                    
                    
                    
                    
                }
                
                
                
                
  
                
                var rules = [NEOnDemandRule]()
                let rule = NEOnDemandRuleConnect()
                rule.interfaceTypeMatch = .any
                rules.append(rule)
                
                self.vpnManager.onDemandRules = rules
                
                
                self.vpnManager.isEnabled = true
                
                if isPrepare{
                    self.vpnManager.saveToPreferences { error in
                        if error != nil {
                            print("VPN Preferences error: 2")
                            rejecter("VPN_ERR", "VPN Preferences error: 2", error)
                        } else {
                            print("VPN Reference Saved")
                            findEventsWithResolver(nil)
                        }
                    }
                }else{
                    self.vpnManager.saveToPreferences { error in
                        if error != nil {
                            print("VPN Preferences error: 2")
                            rejecter("VPN_ERR", "VPN Preferences error: 2", error)
                        } else {
                            var startError: NSError?
                            
                            do {
                                try self.vpnManager.connection.startVPNTunnel()
                            } catch let error as NSError {
                                startError = error
                                print(startError ?? "VPN Manager cannot start tunnel")
                                rejecter("VPN_ERR", "VPN Manager cannot start tunnel", startError)
                            } catch {
                                print("Fatal Error")
                                rejecter("VPN_ERR", "Fatal Error", NSError(domain: "", code: 200, userInfo: nil))
                                fatalError()
                            }
                            if startError != nil {
                                print("VPN Preferences error: 3")
                                print(startError ?? "Start Error")
                                rejecter("VPN_ERR", "VPN Preferences error: 3", startError)
                            } else {
                                print("VPN started successfully..")
                                findEventsWithResolver(nil)
                            }
                        }
                    }
                }
            }
        }
    }
    
    @objc
    func disconnect(_ findEventsWithResolver: RCTPromiseResolveBlock, rejecter: RCTPromiseRejectBlock) -> Void {
        self.vpnManager.connection.stopVPNTunnel()
        findEventsWithResolver(nil)
    }
    
    @objc
    func getCurrentState(_ findEventsWithResolver:RCTPromiseResolveBlock, rejecter:RCTPromiseRejectBlock) -> Void {
        let status = checkNEStatus(status: self.vpnManager.connection.status)
        if(status.intValue < 6){
            findEventsWithResolver(status)
        } else {
            rejecter("VPN_ERR", "Unknown state", NSError())
            fatalError()
        }
    }
    
    @objc
    func getConnectionTimeSecond(_ findEventsWithResolver:RCTPromiseResolveBlock, rejecter: RCTPromiseRejectBlock) -> Void {
        findEventsWithResolver( Int(Date().timeIntervalSince(vpnManager.connection.connectedDate ?? Date())) )
    }
    
    
    @objc
    func getCharonErrorState(_ findEventsWithResolver: RCTPromiseResolveBlock, rejecter: RCTPromiseRejectBlock) -> Void {
        self.sendEvent(withName: "stateChanged", body: [ "state" : checkNEStatus(status: vpnManager.connection.status)  ])

        findEventsWithResolver(nil)
    }
    
}


func checkNEStatus( status:NEVPNStatus ) -> NSNumber {
    switch status {
    case .connecting:
        return 2
    case .connected:
        return 3
    case .disconnecting:
        return 5
    case .disconnected:
        return 1
    case .invalid:
        return 0
    case .reasserting:
        return 4
    @unknown default:
        return 6
    }
}
