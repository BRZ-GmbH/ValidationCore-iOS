import Foundation
import Nimble
import OHHTTPStubs
import OHHTTPStubsSwift
import Quick
import ValidationCore
import XCTest

class ValidationCoreSpec: QuickSpec {
    override func spec() {
        describe("Compatibility Test") {
            var validationCore: ValidationCore!
            let testDataProvider: TestDataProvider! = TestDataProvider()

            beforeEach {}

            for testData in testDataProvider.testData {
                it(testData.testContext.description) {
                    let dateService = TestDateService(testData)
                    let trustlistService = TestTrustlistService(testData, dateService: dateService)
                    validationCore = ValidationCore(trustlistService: trustlistService, dateService: dateService)
                    guard let prefixedEncodedCert = testData.prefixed else {
                        XCTFail("QR code payload missing")
                        return
                    }
                    validationCore.validate(encodedData: prefixedEncodedCert) { result in
                        if let error = result.error {
                            self.map(error, to: testData.expectedResults)
                        } else {
                            self.map(result, to: testData)
                        }
                    }
                }
            }
        }

        describe("Functionality Test") {
            var validationCore: ValidationCore!
            let testDataProvider: TestDataProvider! = TestDataProvider()

            it("can verify signature using X509TrustlistService") {
                let testData = testDataProvider.x509TestData
                let dateService = TestDateService(testData)
                let keyId = Data([172, 54, 144, 238, 131, 97, 204, 150])
                let signatureCerts = [keyId: testData.testContext.signingCertificate!]
                let x509TrustService = X509TrustlistService(base64Encoded: signatureCerts, dateService: dateService)
                validationCore = ValidationCore(trustlistService: x509TrustService, dateService: dateService)
                validationCore.validate(encodedData: testData.prefixed!) { result in
                    expect(result.error).toEventually(beNil())
                }
            }
        }
    }

    private func map(_ validationResult: ValidationResult, to testData: EuTestData) {
        let expectedResults = testData.expectedResults
        if expectedResults.isSchemeValidatable == true {
            expect(validationResult.greenpass).to(beHealthCert(testData.jsonContent))
        }

        if let verifiable = expectedResults.isVerifiable {
            expect(validationResult.isValid == verifiable).to(beTrue())
        }
    }

    private func map(_ error: ValidationError, to expectedResults: ExpectedResults) {
        if expectedResults.isUnprefixed == false {
            expect(error).to(beError(.INVALID_SCHEME_PREFIX))
        }
        if expectedResults.isBase45Decodable == false {
            expect(error).to(beError(.BASE_45_DECODING_FAILED))
        }
        if expectedResults.isExpired == false {
            expect(error).to(beError(.CWT_EXPIRED))
        }
        if expectedResults.isVerifiable == false {
            expect(error).to(satisfyAnyOf(beError(.COSE_DESERIALIZATION_FAILED), beError(.SIGNATURE_INVALID)))
        }
        if expectedResults.isDecodable == false {
            expect(error).to(beError(.CBOR_DESERIALIZATION_FAILED))
        }
        if expectedResults.isKeyUsageMatching == false {
            expect(error).to(beError(.UNSUITABLE_PUBLIC_KEY_TYPE))
        }
    }
}
