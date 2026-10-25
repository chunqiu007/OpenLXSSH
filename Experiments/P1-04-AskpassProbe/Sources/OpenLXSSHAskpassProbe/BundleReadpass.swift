import Foundation
import Darwin
import AskpassPOSIX

public func probeRandomPassphrase() throws -> Data { try randomBytes(32).base64EncodedData() }

public func bundledAskpassHelper() throws -> URL {
    let bundle = Bundle.main
    guard bundle.bundleURL.pathExtension == "app",
          bundle.bundleIdentifier == "org.openlxssh.p104c.broker" else { throw ProbeError.identity }
    let helpers = bundle.bundleURL.appendingPathComponent("Contents/Helpers", isDirectory: true)
    let unresolved = helpers.appendingPathComponent("openlxssh-askpass-helper")
    let helper = unresolved.resolvingSymlinksInPath()
    guard unresolved.standardizedFileURL.path == helper.path,
          helper.deletingLastPathComponent() == helpers.resolvingSymlinksInPath(),
          ap_signed_bundled_helper(helper.path) == 0 else { throw ProbeError.identity }
    return helper
}

// Only this explicitly synthetic self-test decides to answer a real readpass
// challenge. No product automatic-password policy or challenge classifier exists.
public func verifyBundledReadpass(key: URL, expectedPublicKey: Data, passphrase: Data) throws {
    try Limits.validateAnswer(passphrase)
    guard !passphrase.isEmpty else { throw ProbeError.bounds }
    let helper = try bundledAskpassHelper()
    print("PASS bundle helper discovered and verified")
    // Warm Security/Foundation caches before exact per-scenario FD/port baselines.
    do { _ = try FixtureBroker(image: executablePath()) }
    for mode in ["answer", "cancel", "timeout"] {
        let fds = ap_fd_count(), ports = ap_port_count()
        var broker: FixtureBroker? = try FixtureBroker(image: executablePath())
        let service = broker!.serviceName
        do {
            let id = try broker!.launchSystemKeygen(key: key, helper: helper)
            let end = now() + 5
            var requests = 0
            var pendingAtStop: Request?
            while !broker!.allReaped && now() < end {
                broker!.pump()
                for pending in broker!.pending {
                    guard pending.request.kind == .unknownMasked else { throw ProbeError.protocolViolation }
                    if mode == "answer" {
                        requests += 1
                        try broker!.submit(.manual(passphrase), session: id, requestID: pending.request.id, generation: pending.request.generation)
                    } else if mode == "cancel" {
                        pendingAtStop = pending.request
                        requests += 1; broker!.cancel(id)
                    } else { pendingAtStop = pending.request; requests = 1 } // coordinator's real monotonic timeout
                }
            }
            guard broker!.allReaped, broker!.helpersReleased, broker!.openRequests == 0,
                  requests == 1, broker!.rejected.isEmpty else { throw ProbeError.protocolViolation }
            if mode == "answer" {
                guard broker!.exitCode(id) == 0, let output = broker!.systemKeygenOutput(id),
                      output.range(of: passphrase) == nil else { throw ProbeError.protocolViolation }
                let fields = output.split { $0 == 32 || $0 == 10 || $0 == 13 }
                let expected = expectedPublicKey.split { $0 == 32 || $0 == 10 || $0 == 13 }
                guard fields.count == 2, expected.count == 2, fields == expected else { throw ProbeError.protocolViolation }
            } else {
                guard broker!.phase(id) == .closed(mode == "cancel" ? .cancelled : .timeout),
                      broker!.exitCode(id) != 0, let pendingAtStop else { throw ProbeError.protocolViolation }
                do {
                    try broker!.submit(.manual(passphrase), session: id, requestID: pendingAtStop.id, generation: pendingAtStop.generation)
                    throw ProbeError.protocolViolation
                } catch ProbeError.stale { }
            }
            broker = nil
            guard ap_mach_name_unknown(service) == 1, ap_fd_count() == fds,
                  ap_port_count() == ports else { throw ProbeError.protocolViolation }
            print("PASS bundled system ssh-keygen readpass mode=\(mode) PTY=true DISPLAY=false force=true resources_released=true")
            print("POSTEXIT_SERVICE \(service)")
        } catch { broker = nil; throw error }
    }
}
