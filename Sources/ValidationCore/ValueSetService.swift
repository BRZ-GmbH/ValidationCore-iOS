//
//  ValueSetService.swift
//
//
//  Created by Martin Fitzka-Reichart on 14.07.21.
//

import CertLogic
import Foundation

public protocol ValueSetsService {
    func currentValueSets() -> [String: CertLogic.ValueSet]
    func valueSets(completionHandler: @escaping (Swift.Result<[String: CertLogic.ValueSet], ValidationError>) -> Void)
    func updateDataIfNecessary(force: Bool, completionHandler: @escaping (Bool, ValidationError?) -> Void)
    func updateDateService(_ dateService: DateService)
    func cachedValueSets(completionHandler: @escaping (Swift.Result<[String: CertLogic.ValueSet], ValidationError>) -> Void)
}

public class DefaultValueSetsService: SignedDataService<ValueSetContainer>, ValueSetsService {
    private let VALUE_SETS_FILENAME = "valuesets"
    private let VALUE_SETS_KEY_ALIAS = "valuesets_key"
    private let VALUE_SETS_KEYCHAIN_ALIAS = "valuesets_keychain"
    private let LAST_UPDATE_KEY = "last_valuesets_update"

    private var parsedValueSets: [String: CertLogic.ValueSet]?

    public init(dateService: DateService, valueSetsUrl: String, signatureUrl: String, trustAnchor: String, apiToken: String? = nil) {
        super.init(dateService: dateService,
                   dataUrl: valueSetsUrl,
                   signatureUrl: signatureUrl,
                   trustAnchor: trustAnchor,
                   updateInterval: TimeInterval(8.hour),
                   maximumAge: TimeInterval(72.hour),
                   fileName: VALUE_SETS_FILENAME,
                   keyAlias: VALUE_SETS_KEY_ALIAS,
                   legacyKeychainAlias: VALUE_SETS_KEYCHAIN_ALIAS,
                   lastUpdateKey: LAST_UPDATE_KEY,
                   apiToken: apiToken)
    }

    override func didUpdateData() {
        parsedValueSets = cachedData.valueSets.reduce(into: [String: CertLogic.ValueSet]()) {
            guard let jsonData = $1.value.data(using: .utf8) else { return }

            guard let valueSet = try? defaultDecoder.decode(CertLogic.ValueSet.self, from: jsonData) else { return }

            $0[$1.name] = valueSet
        }
    }

    private func mappedValueSets() -> [String: CertLogic.ValueSet] {
        return parsedValueSets ?? [:]
    }

    public func valueSets(completionHandler: @escaping (Swift.Result<[String: CertLogic.ValueSet], ValidationError>) -> Void) {
        updateDataIfNecessary { [weak self] _, _ in
            guard let self = self else { return }

            if self.dataIsExpired() {
                completionHandler(.failure(.DATA_EXPIRED))
                return
            }

            completionHandler(.success(self.mappedValueSets()))
        }
    }
    
    public func cachedValueSets(completionHandler: @escaping (Swift.Result<[String: CertLogic.ValueSet], ValidationError>) -> Void) {
        if self.dataIsExpired() {
            completionHandler(.failure(.DATA_EXPIRED))
            return
        }

        completionHandler(.success(self.mappedValueSets()))
    }
    
    public func currentValueSets() -> [String: CertLogic.ValueSet] {
        return self.mappedValueSets()
    }
}
