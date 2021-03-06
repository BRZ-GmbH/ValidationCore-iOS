import base45_swift
import CocoaLumberjackSwift
import Gzip
import Foundation
import CertLogic
import JSON
import jsonlogic

/// Electronic Health Certificate Validation Core
///
/// This struct provides an interface for validating EHN Health certificates generated by https://dev.a-sit.at/certservice
public struct ValidationCore {
    
    private let PREFIX = "HC1:"
    private let AT_PREFIX = "AT1:"

    private var completionHandler: ((ValidationResult) -> Void)?
    private let trustlistService: TrustlistService
    private let nationalTrustlistService: TrustlistService
    private let businessRulesService: BusinessRulesService
    private let valueSetsService: ValueSetsService
    private let dateService: DateService

    public init(trustlistService: TrustlistService,
                nationalTrustlistService: TrustlistService,
                businessRulesService: BusinessRulesService,
                valueSetsService: ValueSetsService,
                dateService: DateService? = nil) {
        let dateService = dateService ?? DefaultDateService()
        self.dateService = dateService
        self.trustlistService = trustlistService
        self.nationalTrustlistService = nationalTrustlistService
        self.businessRulesService = businessRulesService
        self.valueSetsService = valueSetsService

        DDLog.add(DDOSLogger.sharedInstance)
    }

    // MARK: - Public API

    func decodeCwtAndCose(encodedData: String) -> Swift.Result<(keyId: Data, cwt: CWT, cose: Cose), ValidationError> {
        DDLogDebug("Starting validation")
        guard let unprefixedEncodedString = removeScheme(prefix: PREFIX, from: encodedData) else {
            return .failure(.INVALID_SCHEME_PREFIX)
        }
        
        guard let decodedData = decode(unprefixedEncodedString) else {
            return .failure(.BASE_45_DECODING_FAILED)
        }
        DDLogDebug("Base45-decoded data: \(decodedData.asHex())")
        
        guard let decompressedData = decompress(decodedData) else {
            return .failure(.DECOMPRESSION_FAILED)
        }
        DDLogDebug("Decompressed data: \(decompressedData.asHex())")

        guard let cose = cose(from: decompressedData),
              let keyId = cose.keyId else {
            return .failure(.COSE_DESERIALIZATION_FAILED)
        }
        DDLogDebug("KeyID: \(keyId.encode())")
        
        guard let cwt = CWT(from: cose.payload),
              let euHealthCert = cwt.healthCert,
              euHealthCert.vaccinationExemption == nil else {
            return .failure(.CBOR_DESERIALIZATION_FAILED)
        }
        return .success((keyId, cwt, cose))
    }
    
    func decodeCwtAndCoseForExemption(encodedData: String) -> Swift.Result<(keyId: Data, cwt: CWT, cose: Cose), ValidationError> {
        DDLogDebug("Starting validation")
        guard let unprefixedEncodedString = removeScheme(prefix: AT_PREFIX, from: encodedData) else {
            return .failure(.INVALID_SCHEME_PREFIX)
        }
        
        guard let decodedData = decode(unprefixedEncodedString) else {
            return .failure(.BASE_45_DECODING_FAILED)
        }
        DDLogDebug("Base45-decoded data: \(decodedData.asHex())")
        
        guard let decompressedData = decompress(decodedData) else {
            return .failure(.DECOMPRESSION_FAILED)
        }
        DDLogDebug("Decompressed data: \(decompressedData.asHex())")

        guard let cose = cose(from: decompressedData),
              let keyId = cose.keyId else {
            return .failure(.COSE_DESERIALIZATION_FAILED)
        }
        DDLogDebug("KeyID: \(keyId.encode())")
        
        guard let cwt = CWT(from: cose.payload),
              let healthCert = cwt.healthCert,
              let _ = healthCert.vaccinationExemption else {
            return .failure(.CBOR_DESERIALIZATION_FAILED)
        }
        return .success((keyId, cwt, cose))
    }

    public func decodeCwt(encodedData: String) -> Swift.Result<CWT, ValidationError> {
        let cwtAndCose = decodeCwtAndCose(encodedData: encodedData)

        switch cwtAndCose {
        case .failure(_):
            let cwtAndCoseForExemption = decodeCwtAndCoseForExemption(encodedData: encodedData)
            switch cwtAndCoseForExemption {
                case let .failure(error): return .failure(error)
                case let .success(result): return .success(result.cwt)
            }
        case let .success(result): return .success(result.cwt)
        }
    }

    /// Validate an Base45-encoded EHN health certificate
    public func validate(encodedData: String, _ completionHandler: @escaping (ValidationResult) -> ()) {
        DDLogDebug("Starting validation")
        guard let unprefixedEncodedString = removeScheme(prefix: PREFIX, from: encodedData) else {
            completionHandler(ValidationResult(isValid: false, metaInformation: nil, greenpass: nil, error: .INVALID_SCHEME_PREFIX))
            return
        }
        
        guard let decodedData = decode(unprefixedEncodedString) else {
            completionHandler(ValidationResult(isValid: false, metaInformation: nil, greenpass: nil, error: .BASE_45_DECODING_FAILED))
            return
        }
        DDLogDebug("Base45-decoded data: \(decodedData.asHex())")
        
        guard let decompressedData = decompress(decodedData) else {
            completionHandler(ValidationResult(isValid: false, metaInformation: nil, greenpass: nil, error: .DECOMPRESSION_FAILED))
            return
        }
        DDLogDebug("Decompressed data: \(decompressedData.asHex())")

        guard let cose = cose(from: decompressedData),
              let keyId = cose.keyId else {
            completionHandler(ValidationResult(isValid: false, metaInformation: nil, greenpass: nil, error: .COSE_DESERIALIZATION_FAILED))
            return
        }
        DDLogDebug("KeyID: \(keyId.encode())")
        
        guard let cwt = CWT(from: cose.payload),
              let euHealthCert = cwt.healthCert,
              euHealthCert.vaccinationExemption == nil else {
            completionHandler(ValidationResult(isValid: false, metaInformation: nil, greenpass: nil, error: .CBOR_DESERIALIZATION_FAILED))
            return
        }
        
        trustlistService.key(for: keyId, cwt: cwt, keyType: euHealthCert.type) { result in
            switch result {
            case .success(let key):
                guard cose.hasValidSignature(for: key) else {
                    completionHandler(ValidationResult(isValid: false, metaInformation: MetaInfo(from: cwt), greenpass: euHealthCert, error: .SIGNATURE_INVALID))
                    return
                }
                
                guard cwt.isValid(using: dateService) else {
                    completionHandler(ValidationResult(isValid: false, metaInformation: MetaInfo(from: cwt), greenpass: euHealthCert, error: .CWT_EXPIRED))
                    return
                }

                completionHandler(ValidationResult(isValid: true, metaInformation: MetaInfo(from: cwt), greenpass: euHealthCert, error: nil))
            case .failure(let error): completionHandler(ValidationResult(isValid: false, metaInformation: MetaInfo(from: cwt), greenpass: euHealthCert, error: error))
            }
        }
    }
        
    public func validateExemption(encodedData: String, _ completionHandler: @escaping (ValidationResult)->()) {
        DDLogDebug("Starting AT vaccination exemption validation")
        guard let unprefixedEncodedString = removeScheme(prefix: AT_PREFIX, from: encodedData) else {
            completionHandler(ValidationResult(isValid: false, metaInformation: nil, greenpass: nil, error: .INVALID_SCHEME_PREFIX))
            return
        }
        
        guard let decodedData = decode(unprefixedEncodedString) else {
            completionHandler(ValidationResult(isValid: false, metaInformation: nil, greenpass: nil, error: .BASE_45_DECODING_FAILED))
            return
        }
        DDLogDebug("Base45-decoded data: \(decodedData.asHex())")
        
        guard let decompressedData = decompress(decodedData) else {
            completionHandler(ValidationResult(isValid: false, metaInformation: nil, greenpass: nil, error: .DECOMPRESSION_FAILED))
            return
        }
        DDLogDebug("Decompressed data: \(decompressedData.asHex())")

        guard let cose = cose(from: decompressedData),
              let keyId = cose.keyId else {
            completionHandler(ValidationResult(isValid: false, metaInformation: nil, greenpass: nil, error: .COSE_DESERIALIZATION_FAILED))
            return
        }
        DDLogDebug("KeyID: \(keyId.encode())")
        
        guard let cwt = CWT(from: cose.payload),
              let healthCert = cwt.healthCert,
              let _ = healthCert.vaccinationExemption else {
            completionHandler(ValidationResult(isValid: false, metaInformation: nil, greenpass: nil, error: .CBOR_DESERIALIZATION_FAILED))
            return
        }
        
        nationalTrustlistService.key(for: keyId, cwt: cwt, keyType: healthCert.type) { result in
            switch result {
            case .success(let key):
                guard cose.hasValidSignature(for: key) else {
                    completionHandler(ValidationResult(isValid: false, metaInformation: MetaInfo(from: cwt), greenpass: healthCert, error: .SIGNATURE_INVALID))
                    return
                }
                
                guard cwt.isValid(using: dateService) else {
                    completionHandler(ValidationResult(isValid: false, metaInformation: MetaInfo(from: cwt), greenpass: healthCert, error: .CWT_EXPIRED))
                    return
                }

                completionHandler(ValidationResult(isValid: true, metaInformation: MetaInfo(from: cwt), greenpass: healthCert, error: nil))
            case .failure(let error): completionHandler(ValidationResult(isValid: false, metaInformation: MetaInfo(from: cwt), greenpass: healthCert, error: error))
            }
        }
    }

    public func validateBusinessRules(forCertificate certificate: HealthCert, realTime: Date, validationClock: Date, issuedAt: Date, expiresAt: Date, countryCode: String, region: String? = nil, completionHandler: @escaping ([CertLogic.ValidationResult], Date?, ValidationError?) -> Void) {        
        guard let certificateType = certificate.certificationType else {
            completionHandler([], nil, nil)
            return
        }
        
        businessRulesService.updateDateService(ValidationClockDateService(now: realTime))
        valueSetsService.updateDateService(ValidationClockDateService(now: realTime))

        businessRulesService.cachedBusinessRules { result in
            switch result {
            case let .success(rules):
                self.valueSetsService.cachedValueSets { valueSetResult in
                    switch valueSetResult {
                    case let .success(valueSets):
                        if rules.isEmpty || valueSets.isEmpty {
                            completionHandler([CertLogic.ValidationResult(rule: nil, result: .fail, validationErrors: nil)], nil, nil)
                            return
                        }
                        
                        let filteredRules = rules.filter({ $0.countryCode == countryCode && $0.region == region })
                        let certLogicValueSets = valueSets.mapValues { $0.valueSetValues.map { $0.key } }

                        let engine = CertLogicEngine(schema: parsedEuDgcSchemaV1, rules: filteredRules)
                        let filter = FilterParameter(validationClock: validationClock, countryCode: countryCode, certificationType: certificateType, region: region)
                        let certificatePayload = try! JSONEncoder().encode(certificate)
                        let payloadString = String(data: certificatePayload, encoding: .utf8)!

                        let external = ExternalParameter(validationClock: validationClock, valueSets: certLogicValueSets, exp: expiresAt, iat: issuedAt, issuerCountryCode: countryCode)
                        let result = engine.validate(filter: filter, external: external, payload: payloadString)
                        
                        var validUntilDate: Date? = nil
                        
                        if result.filter({ $0.result == .fail }).isEmpty {
                            let metadataRules = rules.filter({
                                $0.countryCode == countryCode
                                && $0.region == "\(region ?? "")-MD"
                                && ($0.certificateFullType == .general || $0.certificateFullType == certificate.certificationType)
                                && validationClock >= $0.validFromDate && validationClock <= $0.validToDate                                
                            })
                            let validationJSON = getJSONStringForValidation(external: external, payload: payloadString)
                            let jsonObjectForValidation = JSON(string: validationJSON)
                            
                            for metadataRule in metadataRules {
                                do {
                                    validUntilDate = try JsonLogic(metadataRule.logic.description).applyRuleInternal(to: jsonObjectForValidation)
                                    if validUntilDate != nil {
                                        break
                                    }
                                } catch {
                                }
                            }
                        }
                        
                        if result.count == 0 {
                            completionHandler([CertLogic.ValidationResult(rule: nil, result: .passed, validationErrors: nil)], validUntilDate, nil)
                        } else {
                            completionHandler(result, validUntilDate, nil)
                        }
                    case let .failure(error):
                        completionHandler([CertLogic.ValidationResult(rule: nil, result: .fail, validationErrors: nil)], nil, error)
                    }
                }
            case let .failure(error):
                completionHandler([CertLogic.ValidationResult(rule: nil, result: .fail, validationErrors: nil)], nil, error)
            }
        }
    }
    
    public func getCurrentValueSets() -> [String:CertLogic.ValueSet] {
        return valueSetsService.currentValueSets()
    }
    
    private func getJSONStringForValidation(external: ExternalParameter, payload: String) -> String {
      guard let jsonData = try? defaultEncoder.encode(external) else { return ""}
      let externalJsonString = String(data: jsonData, encoding: .utf8)!
      
      var result = ""
      result = "{" + "\"external\":" + "\(externalJsonString)" + "," + "\"payload\":" + "\(payload)"  + "}"
      return result
    }

    public func updateTrustlistAndRules(force: Bool, completionHandler: @escaping (Bool, ValidationError?) -> Void) {
        trustlistService.updateDataIfNecessary(force: force) { updatedTrustlist, trustlistError in
            nationalTrustlistService.updateDataIfNecessary(force: force) { updatedNationalTrustlist, nationalTrustlistError in
                businessRulesService.updateDataIfNecessary(force: force) { updatedBusinessRules, businessRulesError in
                    valueSetsService.updateDataIfNecessary(force: force) { updatedValuesets, valueSetsError in
                        completionHandler(updatedTrustlist || updatedNationalTrustlist || updatedBusinessRules || updatedValuesets, trustlistError ?? nationalTrustlistError ?? businessRulesError ?? valueSetsError)
                    }
                }
            }
        }
    }

    // MARK: - Helper Functions

    /// Strips a given scheme prefix from the encoded EHN health certificate
    private func removeScheme(prefix: String, from encodedString: String) -> String? {
        guard encodedString.starts(with: prefix) else {
            DDLogError("Encoded data string does not seem to include scheme prefix: \(encodedString.prefix(prefix.count))")
            return nil
        }
        return String(encodedString.dropFirst(prefix.count))
    }

    /// Base45-decodes an EHN health certificate
    private func decode(_ encodedData: String) -> Data? {
        return try? encodedData.fromBase45()
    }

    /// Decompress the EHN health certificate using ZLib
    private func decompress(_ encodedData: Data) -> Data? {
        return try? encodedData.gunzipped()
    }

    /// Creates COSE structure from EHN health certificate
    private func cose(from data: Data) -> Cose? {
        return Cose(from: data)
    }
}

public struct ValidationClockDateService: DateService {
    public let now: Date

    public static func forDate(_ date: Date) -> ValidationClockDateService {
        return ValidationClockDateService(now: date)
    }
    
    public func isNowAfter(_ date: Date) -> Bool {
        return now.isAfter(date)
    }

    public func isNowBefore(_ date: Date) -> Bool {
        return now.isBefore(date)
    }
}
