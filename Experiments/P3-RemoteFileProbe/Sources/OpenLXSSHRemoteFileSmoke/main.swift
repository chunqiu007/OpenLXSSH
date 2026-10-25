import OpenLXSSHRemoteFileProbe
import Foundation

@main
struct OpenLXSSHRemoteFileSmoke {
    static func main() throws {
        guard NativeDiagnostics.smoke() == 0 else { throw FileServiceError(.io, operation: "native-smoke") }
        print("libssh2=\(NativeDiagnostics.libssh2)")
        print("crypto=\(NativeDiagnostics.openssl)")
        print("architecture=\(NativeDiagnostics.architecture)")
        // This executable deliberately has no connection or credential flags.
    }
}
