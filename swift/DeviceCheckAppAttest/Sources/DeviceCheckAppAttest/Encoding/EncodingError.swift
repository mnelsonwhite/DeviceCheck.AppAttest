//
//  Created by Matt Nelson-White on 8/1/2023.
//

import Foundation

enum EncodingError: Error
{
    case base64(_ error: Error? = nil)
    case percent(_ error: Error? = nil)
}
