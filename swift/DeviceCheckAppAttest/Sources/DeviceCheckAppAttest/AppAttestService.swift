//
//  Created by Matt Nelson-White on 6/1/2023.
//

import Foundation
import DeviceCheck
import CryptoKit

/// https://developer.apple.com/documentation/devicecheck/establishing_your_app_s_integrity
@available(macOS 11.0, *)
@available(iOS 14.0, *)
@available(macCatalyst 14.0, *)
@available(tvOS 15.0, *)
@available(watchOS 15.0, *)
public class AppAttestService: AppAttestProtocol
{
    private let _service: DCAppAttestService
    private let _keyId: SecretsProvider.Secret<String>
    
    public init?() {
        _service = DCAppAttestService.shared
        _keyId = SecretsProvider().create(
            service: "appattest-key-id",
            account: "device",
            converter: StringConverter()
        )
        
        if !_service.isSupported {
            return nil
        }
    }
    
    public func getKeyId() async throws -> String {
        if let keyId = try _keyId.value {
            return keyId
        }
        
        return try await withCheckedThrowingContinuation { continuation in
            _service.generateKey { keyId, error in
                if let keyIdValue = keyId {
                    do {
                        try self._keyId.set(value: keyIdValue)
                        continuation.resume(returning: keyIdValue)
                    }
                    catch {
                        continuation.resume(throwing: AppAttestError.GetKey(error))
                    }
                }
                else {
                    continuation.resume(throwing: AppAttestError.GetKey(error))
                }
            }
        }
    }
    
    public func getNewKeyId() async throws -> String {
        try _keyId.remove()
        return try await getKeyId()
    }
    
    public func generateAttestation(keyId: String, challenge: Data) async throws -> Data {
        let challengeHash = Data(SHA256.hash(data: challenge))
        
        return try await withCheckedThrowingContinuation { continuation in
            _service.attestKey(keyId, clientDataHash: challengeHash) { attestation, error in
                if let attestationValue = attestation {
                    continuation.resume(returning: attestationValue)
                }
                else if let dcError = error as? DCError, dcError.code == .invalidKey {
                    do {
                        try self._keyId.remove()
                        continuation.resume(throwing: AppAttestError.GenerateAttestation(error))
                    }
                    catch {
                        continuation.resume(throwing: AppAttestError.GenerateAttestation(error))
                    }
                }
                else {
                    continuation.resume(throwing: AppAttestError.GenerateAttestation(error))
                }
            }
        }
    }
    
    public func generateAssertion(keyId: String, requestData: Data) async throws -> Data {
        let clientDataHash = Data(SHA256.hash(data: requestData))
        
        return try await withCheckedThrowingContinuation { continuation in
            _service.generateAssertion(keyId, clientDataHash: clientDataHash) { assertion, error in
                if let assertionValue = assertion {
                    continuation.resume(returning: assertionValue)
                }
                else {
                    continuation.resume(throwing: AppAttestError.GenerateAssertion(error))
                }
            }
        }
    }
    
    public func createAttestationRequest(
        keyId: String,
        correlationId: String,
        attestationPath: String,
        challenge: Data
    ) async throws -> URLRequest {
        guard let attestationUrl = URL(string: attestationPath) else {
            throw AppAttestError.CreateAttestationRequest()
        }
        
        let attestation = try await generateAttestation(keyId: keyId, challenge: challenge)
        
        var request = URLRequest(url: attestationUrl)
        request.setValue(
            "\(NSURLAuthenticationMethodAppAttest) key-id=\(try keyId.percentEncode()) corr-id=\(try correlationId.percentEncode()) attest=\(try attestation.base64Encode().percentEncode())", forHTTPHeaderField: "Authorization"
        )
        request.httpMethod = "POST"
        
        return request
    }
    
    public func createAssertion(keyId: String, request: inout URLRequest) async throws -> Void {
        let data = request.httpBody ?? Data()
        if let assertionData = try? await generateAssertion(keyId: keyId, requestData: data) {
            request.allHTTPHeaderFields?.removeValue(forKey: "Authorization")
            request.setValue("\(NSURLAuthenticationMethodAppAttest) key-id=\(try keyId.percentEncode()) assert=\(try assertionData.base64Encode().percentEncode())", forHTTPHeaderField: "Authorization")
        }
    }
    
    public func sendRequest(session: URLSession, request: inout URLRequest) async throws -> (Data, URLResponse) {
        try await createAssertion(keyId: try await getKeyId(), request: &request)
        
        let corrId = "\(UUID())"
        request.addValue(corrId, forHTTPHeaderField: "X-Correlation-ID")
        
        let (data, response) = try await session.data(for: request)
        
        guard let httpResponse = response as? HTTPURLResponse, httpResponse.statusCode == 401 else {
            return (data, response)
        }
        
        guard let authHeader = httpResponse.value(forHTTPHeaderField: "WWW-Authenticate") else {
            throw AppAttestError.SendRequest("Response does not contain expected WWW-Authenticate header")
        }
        
        let parameters = authHeader.split(separator: " ")[1...].reduce(into: [String.SubSequence: String]()) {
            let pair = $1.split(separator: "=")
            
            if let value = pair[1].removingPercentEncoding {
                $0[pair[0]] = value
            }
        }
        
        guard let challenge = parameters["challenge"],
              let challengeData = Data(base64Encoded: challenge) else {
            throw AppAttestError.SendRequest("Response does not contain valid challenge data")
        }
        
        guard let url = parameters["url"] else {
            throw AppAttestError.SendRequest("Response does not contains valid header url parameter")
        }
        
        let attestRequest = try await createAttestationRequest(keyId: try await getNewKeyId(), correlationId: corrId, attestationPath: url, challenge: challengeData)
        
        let (attestData, attestResponse) = try await session.data(for: attestRequest)
        
        guard let httpAttestResponse = attestResponse as? HTTPURLResponse,
              httpAttestResponse.statusCode == 204 else {
            let attestDataString = String(decoding: attestData, as: UTF8.self)
            print(attestDataString)
            return (data, response)
        }
        
        try await createAssertion(keyId: try await getKeyId(), request: &request)
        return try await session.data(for: request)
    }
}

public let NSURLAuthenticationMethodAppAttest: String = "apple-appattest"
