import Darwin
import Foundation

public enum HostTrustError: Error, Equatable, Sendable {
    case invalidAddress
    case invalidPort
    case invalidUser
    case invalidPath
    case invalidPublicKey
    case unsafeStorage(String)
    case corruptStorage
    case storageChanged
    case systemOperation(String, Int32)
    case publicKeyToolFailed
    case expiredDecision
    case fingerprintMismatch
    case noChangedKey
}

private func hasControlCharacters(_ value: String) -> Bool {
    value.unicodeScalars.contains {
        CharacterSet.controlCharacters.contains($0) ||
        CharacterSet.illegalCharacters.contains($0) ||
        $0.value == 0x2028 || $0.value == 0x2029
    }
}

public struct HostAddress: Hashable, Sendable, CustomStringConvertible {
    public let value: String
    public var description: String { value }

    public init(_ input: String) throws {
        guard !input.isEmpty, input.utf8.count <= 255, !hasControlCharacters(input),
              input.utf8.allSatisfy({ $0 > 32 && $0 < 127 }), !input.hasPrefix("-") else {
            throw HostTrustError.invalidAddress
        }
        var address = input
        if address.hasPrefix("[") && address.hasSuffix("]") {
            address = String(address.dropFirst().dropLast())
            guard address.contains(":") else { throw HostTrustError.invalidAddress }
        }
        if address.contains(":") {
            let parts = address.split(separator: "%", omittingEmptySubsequences: false)
            guard parts.count <= 2 else { throw HostTrustError.invalidAddress }
            var binary = in6_addr()
            guard parts[0].withCString({ inet_pton(AF_INET6, $0, &binary) }) == 1 else {
                throw HostTrustError.invalidAddress
            }
            var buffer = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
            guard inet_ntop(AF_INET6, &binary, &buffer, socklen_t(buffer.count)) != nil else {
                throw HostTrustError.invalidAddress
            }
            var canonical = String(decoding: buffer.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }, as: UTF8.self)
            if parts.count == 2 {
                let zone = String(parts[1])
                guard !zone.isEmpty, zone.utf8.count <= 32, zone == zone.lowercased(),
                      zone.utf8.allSatisfy({ Self.isAlphaNumeric($0) || [45, 46, 95].contains($0) }) else {
                    throw HostTrustError.invalidAddress
                }
                if zone.utf8.allSatisfy({ (48...57).contains($0) }) {
                    guard let index = UInt32(zone), index > 0, String(index) == zone else {
                        throw HostTrustError.invalidAddress
                    }
                }
                canonical += "%" + zone
            }
            value = canonical
            return
        }
        var binary = in_addr()
        if address.withCString({ inet_pton(AF_INET, $0, &binary) }) == 1 {
            var buffer = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
            guard inet_ntop(AF_INET, &binary, &buffer, socklen_t(buffer.count)) != nil else {
                throw HostTrustError.invalidAddress
            }
            let canonical = String(decoding: buffer.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }, as: UTF8.self)
            guard address == canonical else { throw HostTrustError.invalidAddress }
            value = canonical
            return
        }
        // Do not allow legacy abbreviated/ambiguous numeric IPv4 spellings.
        guard !address.utf8.allSatisfy({ (48...57).contains($0) || $0 == 46 }) else {
            throw HostTrustError.invalidAddress
        }
        if address.hasSuffix(".") { address.removeLast() }
        let labels = address.split(separator: ".", omittingEmptySubsequences: false)
        guard address.utf8.count <= 253, labels.allSatisfy({ label in
            !label.isEmpty && label.utf8.count <= 63 &&
            label.utf8.allSatisfy({ Self.isAlphaNumeric($0) || $0 == 45 }) &&
            label.first != "-" && label.last != "-"
        }) else { throw HostTrustError.invalidAddress }
        value = address.lowercased()
    }

    private static func isAlphaNumeric(_ byte: UInt8) -> Bool {
        (48...57).contains(byte) || (65...90).contains(byte) || (97...122).contains(byte)
    }
}

public struct SSHPort: Hashable, Sendable {
    public let value: UInt16
    public init(_ value: Int) throws {
        guard (1...65535).contains(value) else { throw HostTrustError.invalidPort }
        self.value = UInt16(value)
    }
}

public struct SSHUser: Hashable, Sendable {
    public let value: String
    public init(_ value: String) throws {
        guard !value.isEmpty, value.utf8.count <= 256, !hasControlCharacters(value),
              !value.hasPrefix("-"), value.utf8.allSatisfy({
                  (48...57).contains($0) || (65...90).contains($0) || (97...122).contains($0) ||
                  [45, 46, 64, 95, 43, 92].contains($0)
              }) else { throw HostTrustError.invalidUser }
        self.value = value
    }
}

/// Server identity is deliberately independent of the login user or host-list row ID.
public struct HostIdentity: Hashable, Sendable {
    public let address: HostAddress
    public let port: SSHPort
    public init(address: HostAddress, port: SSHPort) {
        self.address = address
        self.port = port
    }
    public var knownHostsName: String {
        port.value == 22 ? address.value : "[\(address.value)]:\(port.value)"
    }

    init(knownHostsName name: String) throws {
        if name.hasPrefix("["), let delimiter = name.range(of: "]:", options: .backwards) {
            let address = String(name[name.index(after: name.startIndex)..<delimiter.lowerBound])
            let port = String(name[delimiter.upperBound...])
            guard let number = Int(port), String(number) == port, number != 22 else {
                throw HostTrustError.corruptStorage
            }
            self.init(address: try HostAddress(address), port: try SSHPort(number))
        } else {
            self.init(address: try HostAddress(name), port: try SSHPort(22))
        }
        guard knownHostsName == name else { throw HostTrustError.corruptStorage }
    }
}

public struct SSHConnection: Hashable, Sendable {
    public let host: HostIdentity
    public let user: SSHUser
    public init(host: HostIdentity, user: SSHUser) {
        self.host = host
        self.user = user
    }
}

public struct AbsolutePath: Hashable, Sendable {
    public let value: String
    public init(_ value: String) throws {
        // ${...} is expanded by OpenSSH in path options; reject $ rather than guess escaping.
        guard value.hasPrefix("/"), !value.hasPrefix("//"), value != "/",
              value.utf8.count < Int(PATH_MAX), !hasControlCharacters(value), !value.contains("$"),
              !value.hasSuffix("/"), value.split(separator: "/", omittingEmptySubsequences: false)
                .dropFirst().allSatisfy({ !$0.isEmpty && $0 != "." && $0 != ".." }) else {
            throw HostTrustError.invalidPath
        }
        self.value = value
    }

    func appending(_ name: String) throws -> AbsolutePath {
        try AbsolutePath(value + "/" + name)
    }
}
