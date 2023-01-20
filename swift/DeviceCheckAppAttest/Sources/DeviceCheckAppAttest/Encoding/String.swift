//
//  Created by Matt Nelson-White on 8/1/2023.
//

import Foundation

extension String {
    func percentEncode(_ withAllowedCharacters: CharacterSet = .alphanumerics) throws -> String {
        guard let value = self.addingPercentEncoding(withAllowedCharacters: .alphanumerics) else {
            throw EncodingError.percent()
        }
        
        return value
    }
}
