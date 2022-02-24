//
//  BusinessRulesService.swift
//
//
//  Created by Martin Fitzka-Reichart on 14.07.21.
//

import CertLogic
import Foundation

public protocol BusinessRulesService {
    func businessRules(completionHandler: @escaping (Swift.Result<[Rule], ValidationError>) -> Void)
    func updateDataIfNecessary(force: Bool, completionHandler: @escaping (Bool, ValidationError?) -> Void)
    func updateDateService(_ dateService: DateService)
    func cachedBusinessRules(completionHandler: @escaping (Swift.Result<[Rule], ValidationError>) -> Void)
}

class DefaultBusinessRulesService: SignedDataService<BusinessRulesContainer>, BusinessRulesService {
    private let BUSINESS_RULES_FILENAME = "businessrules"
    private let BUSINESS_RULES_KEY_ALIAS = "businessrules_key"
    private let BUSINESS_RULES_KEYCHAIN_ALIAS = "businessrules_keychain"
    private let LAST_UPDATE_KEY = "last_businessrules_update"

    private var parsedRules: [Rule]?

    init(dateService: DateService, businessRulesUrl: String, signatureUrl: String, trustAnchor: String, apiToken: String? = nil) {
        super.init(dateService: dateService,
                   dataUrl: businessRulesUrl,
                   signatureUrl: signatureUrl,
                   trustAnchor: trustAnchor,
                   updateInterval: TimeInterval(8.hour),
                   maximumAge: TimeInterval(72.hour),
                   fileName: BUSINESS_RULES_FILENAME,
                   keyAlias: BUSINESS_RULES_KEY_ALIAS,
                   legacyKeychainAlias: BUSINESS_RULES_KEYCHAIN_ALIAS,
                   lastUpdateKey: LAST_UPDATE_KEY,
                   apiToken: apiToken)
    }

    override func didUpdateData() {
        parsedRules = cachedData.entries.compactMap {
            guard let jsonData = $0.rule.data(using: .utf8) else { return nil }

            return try? defaultDecoder.decode(Rule.self, from: jsonData)
        }
    }

    private func parsedBusinessRules() -> [Rule] {
        return parsedRules ?? []
    }

    func businessRules(completionHandler: @escaping (Swift.Result<[Rule], ValidationError>) -> Void) {
        updateDataIfNecessary { [weak self] _, _ in
            self?.cachedBusinessRules(completionHandler: completionHandler)
        }
    }

    func cachedBusinessRules(completionHandler: @escaping (Swift.Result<[Rule], ValidationError>) -> Void) {
        if dataIsExpired() {
            completionHandler(.failure(.DATA_EXPIRED))
            return
        }

        completionHandler(.success(parsedBusinessRules()))
    }
}
