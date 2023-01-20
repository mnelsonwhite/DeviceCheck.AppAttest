//
//  File.swift
//  
//
//  Created by Matt Nelson-White on 7/1/2023.
//

import Foundation

enum AppAttestError: Error {
    case GetKey(_ error: Error? = nil)
    case GenerateAttestation(_ error: Error? = nil)
    case GenerateAssertion(_ error: Error? = nil)
    case CreateAttestationRequest(_ error: Error? = nil)
    case SendRequest(_ message: String? = nil)
}
