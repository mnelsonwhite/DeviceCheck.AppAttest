//
//  File.swift
//  
//
//  Created by Matt Nelson-White on 7/1/2023.
//

import Foundation

@available(macOS 10.15.0, *)
@available(iOS 13.0.0, *)
public protocol AppAttestProtocol {
    func getKeyId() async throws -> String
    func generateAttestation(keyId: String, challenge: Data) async throws -> Data
    func generateAssertion(keyId: String, requestData: Data) async throws -> Data
    func sendRequest(session: URLSession, request: inout URLRequest) async throws -> (Data, URLResponse)
}
