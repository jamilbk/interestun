import Foundation
import NetworkExtension

// Same macOS provider entry pattern as Firezone's system extension.
autoreleasepool { NEProvider.startSystemExtensionMode() }
dispatchMain()
