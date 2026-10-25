import Foundation
import Darwin
import AskpassPOSIX

// A differently signed/identified same-UID fixture has all correlation metadata,
// bypasses helper verification, and sends a well-formed Mach request anyway.
public func runUntrustedClientFixture(environment: [String: String]) -> Int32 {
    do {
        let context = try HelperContext(environment: environment)
        let request = Request(grant: context.grant, prompt: "fixture challenge", hint: nil)
        let inbox = try sendRequest(request, service: context.service)
        do { _ = try receiveMach(inbox.raw, reply: true, timeout: 1000); return 98 }
        catch { return 70 }
    } catch { return 99 }
}

public func temporaryMachServiceIsUnknown(_ name: String) -> Bool { ap_mach_name_unknown(name) == 1 }

public func runStandbyFixture() -> Int32 {
    ap_fixture_signals()
    let end = now() + 4
    while now() < end && ap_fixture_cancelled() == 0 { usleep(5_000) }
    return 0
}
