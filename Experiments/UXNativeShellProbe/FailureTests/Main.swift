import Darwin

@main enum UXNativeFailureOfflineChecks {
    static func main() {
        do {
            let count = try NativeFailureOfflineChecks.run()
            print("Native failure PURE contract/report checks passed: \(count). No I/O, SSH or fixture execution.")
        } catch {
            fputs("Native failure PURE contract/report checks failed.\n", stderr); exit(1)
        }
    }
}
