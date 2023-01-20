//
//  Created by Matt Nelson-White on 6/1/2023.
//

import Foundation

class SecretsProvider {
    private static let dataConverter: DataConverter = DataConverter()
    
    func create(service: String, account: String) -> Secret<Data> {
        return Secret<Data>(service: service, account: account, provider: self, converter: SecretsProvider.dataConverter)
    }
    
    func create<T>(service: String, account: String, converter: Converter<T>) -> Secret<T> {
        return Secret(service: service, account: account, provider: self, converter: converter)
    }
    
    func get(service: String, account: String) throws -> Data? {
        let readSecretsQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnAttributes as String: true,
            kSecReturnData as String: true
        ]
        
        var secretsCopy: AnyObject?
        let resultLoad = SecItemCopyMatching(readSecretsQuery as CFDictionary, &secretsCopy)
        
        guard resultLoad == noErr,
           let resultDictionary = secretsCopy as? [String: Any],
           let resultData = resultDictionary["v_Data"] as? Data else {
            
            if resultLoad == errSecItemNotFound {
                return nil
            }
            
            throw SecretsProviderError.get(resultLoad)
        }
        
        return resultData
    }
    
    private func set(value: Data, service: String, account: String) throws -> Void {
        let addSecretsQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecValueData as String: value
        ]
        
        let resultAdd = SecItemAdd(addSecretsQuery as CFDictionary, nil)
        
        guard resultAdd == noErr else {
            throw SecretsProviderError.set(resultAdd)
        }
    }
    
    private func remove(service: String, account: String) throws -> Void {
        let secretQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]
        
        let resultDelete = SecItemDelete(secretQuery as CFDictionary)
        
        guard resultDelete == noErr else {
            throw SecretsProviderError.remove(resultDelete)
        }
    }
    
    public class Secret<T> {
        typealias T = T
        
        private let _service: String
        private let _account: String
        private let _provider: SecretsProvider
        private let _converter: Converter<T>
        private var _value: T?
        
        var value: T? {
            get throws {
                if let value = _value {
                    return value
                }
                
                let data = try _provider.get(service: _service, account: _account)
                
                if let dataValue = data {
                    let value = try _converter.To(data: dataValue)
                    _value = value
                    return value
                }
                
                return nil
            }
        }
        
        func set(value: T) throws {
            _value = value
            try _provider.set(value: try _converter.From(value: value), service: _service, account: _account)
        }
        
        func remove() throws {
            _value = nil
            try _provider.remove(service: _service, account: _account)
        }
        
        init(service: String, account: String, provider: SecretsProvider, converter: Converter<T>) {
            _service = service
            _account = account
            _provider = provider
            _converter = converter
        }
    }
}

enum SecretsProviderError: Error {
    case get(_ statusCode: OSStatus)
    case set(_ statusCode: OSStatus)
    case remove(_ statusCode: OSStatus)
}

class Converter<T> {
    private let _to: (Data) throws -> T
    private let _from: (T) throws -> Data
    
    
    init(to: @escaping (Data) throws -> T, from: @escaping  (T) throws -> Data) {
        _to = to
        _from = from
    }
    
    func To(data: Data) throws -> T {
        return try _to(data)
    }
    
    func From(value: T) throws -> Data {
        return try _from(value)
    }
}

class DataConverter: Converter<Data> {
    init() {
        super.init(
            to: { data in
                return data
            },
            from: { value in
                return value
            }
        )
    }
}

class StringConverter: Converter<String> {
    init() {
        super.init(
            to: { data in
                return NSString(data: data, encoding: String.Encoding.utf8.rawValue)! as String
            },
            from: { value in
                return value.data(using: .utf8)!
            }
        )
    }
}
