import Darwin
import Foundation

/// Records both actual clock endpoints. Elapsed values are not inferred from a
/// planned duration, loop count, sample count, or CPU time.
public struct TimingEvidence: Encodable, Equatable, Sendable {
    public let start: ClockReading
    public let end: ClockReading
    public let monotonicElapsedSeconds: Double
    public let wallElapsedSeconds: Double
    public let continuousElapsedSeconds: Double
    public init(start: ClockReading, end: ClockReading) {
        self.start = start; self.end = end
        monotonicElapsedSeconds = end.monotonic - start.monotonic
        wallElapsedSeconds = end.wallUnix - start.wallUnix
        continuousElapsedSeconds = end.continuous - start.continuous
    }
}

/// Deletes only the exact empty Transport workspace after public session cleanup.
/// Does not follow links, recursively remove directories, touch credentials, or
/// erase JSONL. A leftover configuration/session directory is a cleanup failure.
public enum ExactWorkspaceCleanup {
    public static func removeEmptySessions(inExactRunRoot root: String) throws {
        try PrivateMaterial.check(root, directory: true)
        let name = URL(fileURLWithPath: root).lastPathComponent
        guard name.hasPrefix("stability-"), let id = UUID(uuidString: String(name.dropFirst(10))),
              name == "stability-" + id.uuidString else { throw StabilityError.unsafePath }
        let path = root + "/sessions"
        try PrivateMaterial.check(path, directory: true)
        guard rmdir(path) == 0 else { throw StabilityError.cleanupIncomplete }
    }
}
