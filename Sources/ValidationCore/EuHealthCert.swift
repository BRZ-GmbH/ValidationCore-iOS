//
//  EuHealthCert.swift
//
//
//  Created by Dominik Mocher on 14.04.21.
//

import Foundation
import SwiftCBOR

public struct EuHealthCert: Codable {
    public let person: Person
    public let dateOfBirth: String
    public let version: String
    public let vaccinations: [Vaccination]?
    public let recovery: [Recovery]?
    public let tests: [Test]?

    public var type: CertType {
        switch self {
        case _ where vaccinations != nil && vaccinations?.count ?? 0 > 0:
            return .vaccination
        case _ where recovery != nil && recovery?.count ?? 0 > 0:
            return .recovery
        default:
            return .test
        }
    }

    private enum CodingKeys: String, CodingKey {
        case person = "nam"
        case dateOfBirth = "dob"
        case vaccinations = "v"
        case recovery = "r"
        case tests = "t"
        case version = "ver"
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        person = try container.decode(Person.self, forKey: .person)
        version = try container.decode(String.self, forKey: .version)
        dateOfBirth = try container.decode(String.self, forKey: .dateOfBirth)
        vaccinations = try? container.decode([Vaccination].self, forKey: .vaccinations)
        tests = try? container.decode([Test].self, forKey: .tests)
        recovery = try? container.decode([Recovery].self, forKey: .recovery)

        if (vaccinations.moreThanOne && (recovery.moreThanOne || tests.moreThanOne)) ||
            tests.moreThanOne && (recovery.moreThanOne || vaccinations.moreThanOne) ||
            recovery.moreThanOne && (tests.moreThanOne || vaccinations.moreThanOne) ||
            !(vaccinations.exactlyOne || recovery.exactlyOne || tests.exactlyOne) {
            throw ValidationError.CBOR_DESERIALIZATION_FAILED
        }
    }
}

public struct Person: Codable {
    public let givenName: String?
    public let standardizedGivenName: String?
    public let familyName: String?
    public let standardizedFamilyName: String

    private enum CodingKeys: String, CodingKey {
        case givenName = "gn"
        case standardizedGivenName = "gnt"
        case familyName = "fn"
        case standardizedFamilyName = "fnt"
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        givenName = try? container.decode(String.self, forKey: .givenName)
        standardizedGivenName = try? container.decode(String.self, forKey: .standardizedGivenName)
        familyName = try? container.decode(String.self, forKey: .familyName)
        standardizedFamilyName = try container.decode(String.self, forKey: .standardizedFamilyName)
    }
}

public struct Vaccination: Codable {
    public let disease: String
    public let vaccine: String
    public let medicinialProduct: String
    public let marketingAuthorizationHolder: String
    public let doseNumber: UInt64
    public let totalDoses: UInt64
    public let vaccinationDate: String
    public let country: String
    public let certificateIssuer: String
    public let certificateIdentifier: String

    private enum CodingKeys: String, CodingKey {
        case disease = "tg"
        case vaccine = "vp"
        case medicinialProduct = "mp"
        case marketingAuthorizationHolder = "ma"
        case doseNumber = "dn"
        case totalDoses = "sd"
        case vaccinationDate = "dt"
        case country = "co"
        case certificateIssuer = "is"
        case certificateIdentifier = "ci"
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        disease = try container.decode(String.self, forKey: .disease).trimmingCharacters(in: .whitespacesAndNewlines)
        vaccine = try container.decode(String.self, forKey: .vaccine).trimmingCharacters(in: .whitespacesAndNewlines)
        medicinialProduct = try container.decode(String.self, forKey: .medicinialProduct).trimmingCharacters(in: .whitespacesAndNewlines)
        marketingAuthorizationHolder = try container.decode(String.self, forKey: .marketingAuthorizationHolder).trimmingCharacters(in: .whitespacesAndNewlines)
        doseNumber = try container.decode(UInt64.self, forKey: .doseNumber)
        guard 1 ..< 10 ~= doseNumber else {
            throw ValidationError.CBOR_DESERIALIZATION_FAILED
        }
        totalDoses = try container.decode(UInt64.self, forKey: .totalDoses)
        guard 1 ..< 10 ~= totalDoses else {
            throw ValidationError.CBOR_DESERIALIZATION_FAILED
        }
        vaccinationDate = try container.decode(String.self, forKey: .vaccinationDate)
        guard vaccinationDate.isValidIso8601Date() else {
            throw ValidationError.CBOR_DESERIALIZATION_FAILED
        }
        country = try container.decode(String.self, forKey: .country).trimmingCharacters(in: .whitespacesAndNewlines)
        certificateIssuer = try container.decode(String.self, forKey: .certificateIssuer)
        certificateIdentifier = try container.decode(String.self, forKey: .certificateIdentifier)
    }
}

public struct Test: Codable {
    public let disease: String
    public let type: String
    public let testName: String?
    public let manufacturer: String?
    public let timestampSample: String
    public let timestampResult: String?
    public let result: String
    public let testCenter: String?
    public let country: String
    public let certificateIssuer: String
    public let certificateIdentifier: String

    private enum CodingKeys: String, CodingKey {
        case disease = "tg"
        case type = "tt"
        case testName = "nm"
        case manufacturer = "ma"
        case timestampSample = "sc"
        case timestampResult = "dr"
        case result = "tr"
        case testCenter = "tc"
        case country = "co"
        case certificateIssuer = "is"
        case certificateIdentifier = "ci"
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        disease = try container.decode(String.self, forKey: .disease).trimmingCharacters(in: .whitespacesAndNewlines)
        type = try container.decode(String.self, forKey: .type).trimmingCharacters(in: .whitespacesAndNewlines)
        testName = try? container.decode(String.self, forKey: .testName)
        manufacturer = try? container.decode(String.self, forKey: .manufacturer).trimmingCharacters(in: .whitespacesAndNewlines)
        timestampSample = try container.decode(String.self, forKey: .timestampSample)
        guard timestampSample.isValidIso8601DateTime() else {
            throw ValidationError.CBOR_DESERIALIZATION_FAILED
        }
        timestampResult = try? container.decode(String.self, forKey: .timestampResult)
        if let timestampResult = timestampResult, !timestampResult.isValidIso8601DateTime() {
            throw ValidationError.CBOR_DESERIALIZATION_FAILED
        }
        result = try container.decode(String.self, forKey: .result).trimmingCharacters(in: .whitespacesAndNewlines)
        testCenter = try? container.decode(String.self, forKey: .testCenter)
        country = try container.decode(String.self, forKey: .country).trimmingCharacters(in: .whitespacesAndNewlines)
        certificateIssuer = try container.decode(String.self, forKey: .certificateIssuer)
        certificateIdentifier = try container.decode(String.self, forKey: .certificateIdentifier)
    }
}

public struct Recovery: Codable {
    public let disease: String
    public let dateFirstPositiveTest: String
    public let countryOfTest: String
    public let certificateIssuer: String
    public let validFrom: String
    public let validUntil: String
    public let certificateIdentifier: String

    private enum CodingKeys: String, CodingKey {
        case disease = "tg"
        case dateFirstPositiveTest = "fr"
        case countryOfTest = "co"
        case certificateIssuer = "is"
        case validFrom = "df"
        case validUntil = "du"
        case certificateIdentifier = "ci"
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        disease = try container.decode(String.self, forKey: .disease).trimmingCharacters(in: .whitespacesAndNewlines)
        let dateFirstPositiveTest = try container.decode(String.self, forKey: .dateFirstPositiveTest)
        guard dateFirstPositiveTest.isValidIso8601Date() else {
            throw ValidationError.CBOR_DESERIALIZATION_FAILED
        }
        self.dateFirstPositiveTest = dateFirstPositiveTest
        countryOfTest = try container.decode(String.self, forKey: .countryOfTest).trimmingCharacters(in: .whitespacesAndNewlines)
        validFrom = try container.decode(String.self, forKey: .validFrom)
        guard validFrom.isValidIso8601Date() else {
            throw ValidationError.CBOR_DESERIALIZATION_FAILED
        }
        validUntil = try container.decode(String.self, forKey: .validUntil)
        guard validUntil.isValidIso8601Date() else {
            throw ValidationError.CBOR_DESERIALIZATION_FAILED
        }
        certificateIssuer = try container.decode(String.self, forKey: .certificateIssuer)
        certificateIdentifier = try container.decode(String.self, forKey: .certificateIdentifier)
    }
}
