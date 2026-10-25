import Darwin
import FileKeychainCandidate
import Foundation

@main
struct FileKeychainCandidateCLI {
    static func main() {
        let arguments = CommandLine.arguments
        guard arguments.count == 3 || arguments.count == 4,
              ["create", "read", "deny", "wrong-reference", "cleanup"].contains(arguments[1]) else {
            print("FILE CANDIDATE usage: create|read|deny|cleanup <exact-ticket-path> [memory-pipe-fd]")
            exit(64)
        }
        var result: Int32 = 0
        do {
            let process = try FileKeychainNoUIProcess()
            print("FILE CANDIDATE process_optional_interaction_disabled: true")
            do {
                try FileCandidateFixture.execute(arguments[1], ticketURL: URL(fileURLWithPath: arguments[2]),
                                                 proofFD: arguments.count == 4 ? Int32(arguments[3]) : nil,
                                                 process: process)
            } catch let error as FileCandidateFailure {
                print("FILE CANDIDATE INCOMPLETE: \(error)")
                result = 2
            } catch {
                print("FILE CANDIDATE INCOMPLETE: details redacted")
                result = 1
            }
            let restored = try process.finish()
            print("FILE CANDIDATE process_interaction_flag_restored: \(restored)")
        } catch {
            print("FILE CANDIDATE noninteractive_guard_failed: true; no authorization supplied")
            result = 3
        }
        exit(result)
    }
}
