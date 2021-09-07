//
//  SignedDataService.swift
//
//
//  Created by Martin Fitzka-Reichart on 14.07.21.
//

import CocoaLumberjackSwift
import Foundation
import Security
import SwiftCBOR

protocol SignedData: Codable {
    var hash: Data? { get set }
    var isEmpty: Bool { get }
    init()
}

class SignedDataService<T: SignedData> {
    private let dataUrl: String
    private let signatureUrl: String
    private let apiToken: String?
    private let trustAnchor: String
    var dateService: DateService
    private let fileStorage: FileStorage
    var cachedData: T
    private let updateInterval: TimeInterval
    private let maximumAge: TimeInterval
    var lastUpdate: Date {
        get {
            if let isoDate = UserDefaults().string(forKey: lastUpdateKey),
               let date = ISO8601DateFormatter().date(from: isoDate) {
                return date
            }
            return Date(timeIntervalSince1970: 0)
        }
        set {
            let isoDate = ISO8601DateFormatter().string(from: newValue)
            UserDefaults().set(isoDate, forKey: lastUpdateKey)
        }
    }

    private let fileName: String
    private let keyAlias: String
    private let legacyKeychainAlias: String
    private let lastUpdateKey: String

    init(dateService: DateService,
         dataUrl: String,
         signatureUrl: String,
         trustAnchor: String,
         updateInterval: TimeInterval,
         maximumAge: TimeInterval,
         fileName: String,
         keyAlias: String,
         legacyKeychainAlias: String,
         lastUpdateKey: String,
         apiToken: String? = nil) {
        self.dataUrl = dataUrl
        self.signatureUrl = signatureUrl
        self.trustAnchor = trustAnchor
        fileStorage = FileStorage()
        self.dateService = dateService
        self.updateInterval = updateInterval
        self.maximumAge = maximumAge
        self.fileName = fileName
        self.keyAlias = keyAlias
        self.legacyKeychainAlias = legacyKeychainAlias
        self.lastUpdateKey = lastUpdateKey
        self.apiToken = apiToken
        cachedData = T()

        loadCachedData()
        if cachedData.isEmpty {
            lastUpdate = Date(timeIntervalSince1970: 0)
        }
        updateSignatureAndDataIfNecessary { _, _ in }
        removeLegacyKeychainData()
    }

    func updateDateService(_ dateService: DateService) {
        self.dateService = dateService
    }

    public func updateDataIfNecessary(force: Bool = false, completionHandler: @escaping (Bool, ValidationError?) -> Void) {
        if dateService.isNowBefore(lastUpdate.addingTimeInterval(updateInterval)) && !cachedData.isEmpty && !force {
            DDLogDebug("Skipping data update...")
            completionHandler(false, nil)
            return
        }

        updateSignatureAndDataIfNecessary { updated, error in
            if let error = error {
                DDLogError("Cannot refresh data: \(error)")
            }

            completionHandler(updated, error)
        }
    }

    private func updateSignatureAndDataIfNecessary(completionHandler: @escaping (Bool, ValidationError?) -> Void) {
        updateDetachedSignature { result in
            switch result {
            case let .success(hash):
                if hash != self.cachedData.hash {
                    self.updateData(for: hash, completionHandler)
                    return
                } else {
                    self.lastUpdate = self.dateService.now
                }
                completionHandler(false, nil)
            case let .failure(error):
                completionHandler(false, error)
            }
        }
    }

    private func updateData(for hash: Data, _ completionHandler: @escaping (Bool, ValidationError?) -> Void) {
        guard let request = defaultRequest(to: dataUrl) else {
            completionHandler(true, .TRUST_SERVICE_ERROR)
            return
        }

        URLSession.shared.dataTask(with: request) { body, response, error in
            guard self.isResponseValid(response, error), let body = body else {
                DDLogError("Cannot query signed data service")
                completionHandler(true, .TRUST_SERVICE_ERROR)
                return
            }
            guard self.refreshData(from: body, for: hash) else {
                completionHandler(true, .TRUST_SERVICE_ERROR)
                return
            }

            self.lastUpdate = self.dateService.now

            completionHandler(true, nil)
        }.resume()
    }

    private func updateDetachedSignature(completionHandler: @escaping (Result<Data, ValidationError>) -> Void) {
        guard let request = defaultRequest(to: signatureUrl) else {
            completionHandler(.failure(.TRUST_SERVICE_ERROR))
            return
        }

        URLSession.shared.dataTask(with: request) { body, response, error in
            guard self.isResponseValid(response, error), let body = body else {
                completionHandler(.failure(.TRUST_SERVICE_ERROR))
                return
            }
            guard let cose = Cose(from: body),
                  let trustAnchorKey = self.trustAnchorKey(),
                  cose.hasValidSignature(for: trustAnchorKey) else {
                completionHandler(.failure(.TRUST_LIST_SIGNATURE_INVALID))
                return
            }
            guard let cwt = CWT(from: cose.payload),
                  let trustlistHash = cwt.sub else {
                completionHandler(.failure(.TRUST_SERVICE_ERROR))
                return
            }
            guard cwt.isAlreadyValid(using: self.dateService) else {
                completionHandler(.failure(.TRUST_LIST_NOT_YET_VALID))
                return
            }

            guard cwt.isNotExpired(using: self.dateService) else {
                completionHandler(.failure(.TRUST_LIST_EXPIRED))
                return
            }

            completionHandler(.success(trustlistHash))
        }.resume()
    }

    private func refreshData(from data: Data, for hash: Data) -> Bool {
        guard let cbor = try? CBORDecoder(input: data.bytes).decodeItem(),
              var decodedData = try? CodableCBORDecoder().decode(T.self, from: cbor.asData()) else {
            return false
        }
        decodedData.hash = hash
        cachedData = decodedData
        storeData()
        didUpdateData()
        return true
    }

    func didUpdateData() {}

    private func defaultRequest(to url: String) -> URLRequest? {
        guard let url = URL(string: url) else {
            return nil
        }
        var request = URLRequest(url: url)
        request.addValue("application/octet-stream", forHTTPHeaderField: "Accept")
        if let apiToken = apiToken {
            request.addValue(apiToken, forHTTPHeaderField: "X-Token")
        }
        return request
    }

    private func isResponseValid(_ response: URLResponse?, _ error: Error?) -> Bool {
        guard error == nil,
              let status = (response as? HTTPURLResponse)?.statusCode,
              status == 200 else {
            return false
        }
        return true
    }

    private func trustAnchorKey() -> SecKey? {
        guard let certData = Data(base64Encoded: trustAnchor),
              let certificate = SecCertificateCreateWithData(nil, certData as CFData),
              let secKey = SecCertificateCopyKey(certificate) else {
            return nil
        }
        return secKey
    }

    func dataIsExpired() -> Bool {
        if dateService.isNowBefore(lastUpdate.addingTimeInterval(maximumAge)) {
            return false
        }
        return true
    }
}

extension SignedDataService {
    // MARK: Cached Data Storage and Retrieval

    private func storeData() {
        guard let encodedData = try? JSONEncoder().encode(cachedData) else {
            DDLogError("Cannot encode data for storing")
            return
        }
        if #available(iOS 13.0, *) {
            CryptoService.createKeyAndEncrypt(data: encodedData, with: self.keyAlias, completionHandler: { result in
                switch result {
                case let .success(data):
                    if !self.fileStorage.writeProtectedFileToDisk(fileData: data, with: self.fileName) {
                        DDLogError("Cannot write data to disk")
                    }
                case let .failure(error): DDLogError(error)
                }
            })
        } else {
            storeLegacyData(encodedData: encodedData)
        }
    }

    func loadCachedData() {
        if #available(iOS 13.0, *) {
            if let encodedData = fileStorage.loadProtectedFileFromDisk(with: self.fileName) {
                CryptoService.decrypt(ciphertext: encodedData, with: self.keyAlias) { result in
                    switch result {
                    case let .success(plaintext):
                        if let data = try? JSONDecoder().decode(T.self, from: plaintext) {
                            self.cachedData = data
                        }
                    case let .failure(error): DDLogError("Cannot load cached trust list: \(error)")
                    }
                }
            }
        } else {
            loadCachedLegacyData()
        }
        didUpdateData()
    }
}

extension SignedDataService {
    // MARK: iOS 12 support for missing CryptoKit

    func removeLegacyKeychainData() {
        if #available(iOS 13.0, *) {
            removeLegacyKeychainDataEntries()
        }
    }

    private func removeLegacyKeychainDataEntries() {
        let query = [kSecClass: kSecClassGenericPassword,
                     kSecAttrLabel: legacyKeychainAlias,
                     kSecAttrAccount: legacyKeychainAlias,
                     kSecAttrService: legacyKeychainAlias] as [String: Any]
        let status = SecItemDelete(query as CFDictionary)

        if status != errSecSuccess {
            let query = [kSecClass: kSecClassGenericPassword,
                         kSecAttrLabel: legacyKeychainAlias] as [String: Any]
            SecItemDelete(query as CFDictionary)
        }
    }

    private func storeLegacyData(encodedData: Data) {
        removeLegacyKeychainDataEntries()

        guard let accessFlags = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            [],
            nil
        ) else {
            DDLogError(ValidationError.KEYSTORE_ERROR)
            return
        }
        let updateQuery = [kSecClass: kSecClassGenericPassword,
                           kSecAttrLabel: legacyKeychainAlias,
                           kSecAttrService: legacyKeychainAlias,
                           kSecAttrAccount: legacyKeychainAlias] as [String: Any]

        let updateAttributes = [kSecValueData: encodedData] as [String: Any]

        let status = SecItemUpdate(updateQuery as CFDictionary, updateAttributes as CFDictionary)
        if status == errSecItemNotFound {
            let addQuery = [kSecClass: kSecClassGenericPassword,
                            kSecAttrLabel: legacyKeychainAlias,
                            kSecAttrService: legacyKeychainAlias,
                            kSecAttrAccount: legacyKeychainAlias,
                            kSecAttrAccessControl: accessFlags,
                            kSecValueData: encodedData] as [String: Any]
            let addStatus = SecItemAdd(addQuery as CFDictionary, nil)
            if addStatus != errSecSuccess {
                DDLogError(ValidationError.KEYSTORE_ERROR)
            }
        } else if status != errSecSuccess {
            DDLogError(ValidationError.KEYSTORE_ERROR)
        }
    }

    private func loadCachedLegacyData() {
        let query = [kSecClass: kSecClassGenericPassword,
                     kSecAttrLabel: legacyKeychainAlias,
                     kSecAttrService: legacyKeychainAlias,
                     kSecAttrAccount: legacyKeychainAlias,
                     kSecReturnData: true] as [String: Any]

        var item: CFTypeRef?
        switch SecItemCopyMatching(query as CFDictionary, &item) {
        case errSecSuccess:
            if let plaintext = item as? Data {
                if let data = try? JSONDecoder().decode(T.self, from: plaintext) {
                    cachedData = data
                    return
                }
            }
        case errSecItemNotFound:
            let query = [kSecClass: kSecClassGenericPassword,
                         kSecAttrLabel: legacyKeychainAlias,
                         kSecReturnData: true] as [String: Any]

            var item: CFTypeRef?
            switch SecItemCopyMatching(query as CFDictionary, &item) {
            case errSecSuccess:
                if let plaintext = item as? Data {
                    if let data = try? JSONDecoder().decode(T.self, from: plaintext) {
                        cachedData = data
                    }
                }
            default: DDLogError(ValidationError.KEYSTORE_ERROR)
            }

        default: DDLogError(ValidationError.KEYSTORE_ERROR)
        }
    }
}
