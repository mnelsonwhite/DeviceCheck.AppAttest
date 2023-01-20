//
//  Created by Matt Nelson-White on 8/1/2023.
//

import Foundation

extension Data {
    func base64Encode() throws -> String {
        return self.base64EncodedString()
    }
}
