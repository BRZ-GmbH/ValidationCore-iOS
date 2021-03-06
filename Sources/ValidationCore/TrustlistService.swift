//
//  File.swift
//
//
//  Created by Dominik Mocher on 26.04.21.
//

import Foundation

public protocol TrustlistService {
    func key(for keyId: Data, keyType: CertType, completionHandler: @escaping (Result<SecKey, ValidationError>) -> Void)
    func key(for keyId: Data, cwt: CWT, keyType: CertType, completionHandler: @escaping (Result<SecKey, ValidationError>) -> Void)
    func updateDataIfNecessary(force: Bool, completionHandler: @escaping (Bool, ValidationError?) -> Void)
    func updateDateService(_ dateService: DateService)
    func cachedKey(from keyId: Data, for keyType: CertType, cwt: CWT?, _ completionHandler: @escaping (Result<SecKey, ValidationError>) -> Void)
}

public class DefaultTrustlistService: SignedDataService<TrustList>, TrustlistService {
    private let TRUSTLIST_FILENAME = "trustlist"
    private let TRUSTLIST_KEY_ALIAS = "trustlist_key"
    private let TRUSTLIST_KEYCHAIN_ALIAS = "trustlist_keychain"
    private let LAST_UPDATE_KEY = "last_trustlist_update"
    
    private let AT_TRUSTLIST_FILENAME = "at_trustlist"
    private let AT_TRUSTLIST_KEY_ALIAS = "at_trustlist_key"
    private let AT_TRUSTLIST_KEYCHAIN_ALIAS = "at_trustlist_keychain"
    private let AT_LAST_UPDATE_KEY = "at_last_trustlist_update"
    
    public enum TrustlistSource {
        case euDgc
        case atNational
    }

    public init(dateService: DateService,
                trustlistUrl: String,
                signatureUrl: String,
                trustAnchor: String,
                source: TrustlistSource,
                apiToken: String? = nil
    ) {
        super.init(dateService: dateService,
                   dataUrl: trustlistUrl,
                   signatureUrl: signatureUrl,
                   trustAnchor: trustAnchor,
                   updateInterval: TimeInterval(8.hour),
                   maximumAge: TimeInterval(72.hour),
                   fileName: source == .euDgc ? TRUSTLIST_FILENAME : AT_TRUSTLIST_FILENAME,
                   keyAlias: source == .euDgc ? TRUSTLIST_KEY_ALIAS : AT_TRUSTLIST_KEY_ALIAS,
                   legacyKeychainAlias: source == .euDgc ? TRUSTLIST_KEYCHAIN_ALIAS : AT_TRUSTLIST_KEYCHAIN_ALIAS,
                   lastUpdateKey: source == .euDgc ? LAST_UPDATE_KEY : AT_LAST_UPDATE_KEY,
                   apiToken: apiToken)
    }

    public func key(for keyId: Data, keyType: CertType, completionHandler: @escaping (Result<SecKey, ValidationError>) -> Void) {
        key(for: keyId, keyType: keyType, cwt: nil, completionHandler: completionHandler)
    }

    public func key(for keyId: Data, cwt: CWT, keyType: CertType, completionHandler: @escaping (Result<SecKey, ValidationError>) -> Void) {
        return key(for: keyId, keyType: keyType, cwt: cwt, completionHandler: completionHandler)
    }

    private func key(for keyId: Data, keyType: CertType, cwt: CWT?, completionHandler: @escaping (Result<SecKey, ValidationError>) -> Void) {
        updateDataIfNecessary { _, _ in
            self.cachedKey(from: keyId, for: keyType, cwt: cwt, completionHandler)
        }
    }
    
    public func cachedKey(from keyId: Data, for keyType: CertType, cwt: CWT?, _ completionHandler: @escaping (Result<SecKey, ValidationError>) -> Void) {
        if dataIsExpired() {
            completionHandler(.failure(.DATA_EXPIRED))
            return
        }

        guard let entry = cachedData.entry(for: keyId) else {
            completionHandler(.failure(.KEY_NOT_IN_TRUST_LIST))
            return
        }
        guard entry.isValid(for: dateService) else {
            completionHandler(.failure(.PUBLIC_KEY_EXPIRED))
            return
        }
        guard entry.isSuitable(for: keyType) else {
            completionHandler(.failure(.UNSUITABLE_PUBLIC_KEY_TYPE))
            return
        }

        if let cwtIssuedAt = cwt?.issuedAt,
           let cwtExpiresAt = cwt?.expiresAt,
           let certNotBefore = entry.notBefore,
           let certNotAfter = entry.notAfter {
            if cwtIssuedAt.isBefore(certNotBefore) || cwtIssuedAt.isAfter(certNotAfter) || cwtExpiresAt.isAfter(certNotAfter) {
                completionHandler(.failure(.CWT_EXPIRED))
                return
            }
        }

        guard let secKey = entry.publicKey else {
            completionHandler(.failure(.KEY_CREATION_ERROR))
            return
        }
        completionHandler(.success(secKey))
    }
}
