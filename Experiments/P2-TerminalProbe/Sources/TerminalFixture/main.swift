import Darwin
import Foundation

private func output(_ text: String) {
    let bytes = Array(text.utf8)
    var offset = 0
    while offset < bytes.count {
        let count = bytes.withUnsafeBytes { Darwin.write(STDOUT_FILENO, $0.baseAddress!.advanced(by: offset), bytes.count - offset) }
        if count > 0 { offset += count } else if errno != EINTR { break }
    }
}
private func size() -> String {
    var size = winsize()
    _ = ioctl(STDIN_FILENO, TIOCGWINSZ, &size)
    return "\(size.ws_col)x\(size.ws_row)"
}
private let sample = "中文 / UTF-8 / 😀 👩🏽‍💻 / e\u{301} / 组合字符"
private let args = Array(CommandLine.arguments.dropFirst())
if args.first == "--exit" { output("FINAL-TAIL \(sample)\r\n"); exit(Int32(args.last ?? "0") ?? 0) }
if args.first == "--ignore-term" { signal(SIGTERM, SIG_IGN) }
var original = termios()
_ = tcgetattr(STDIN_FILENO, &original)
var raw = original
cfmakeraw(&raw)
_ = tcsetattr(STDIN_FILENO, TCSANOW, &raw)
defer { _ = tcsetattr(STDIN_FILENO, TCSANOW, &original) }
if args.first == "--stream", let count = Int(args.last ?? ""), count <= 1_000_000 {
    for index in 0..<count { output(String(format: "STREAM-%06d 中文 é 😀\r\n", index)) }
    output("STREAM-END\r\n")
    exit(0)
}
output("\u{1b}[?2004hOpenLXSSH LOCAL FIXTURE — no SSH/network/config/credentials\r\n")
output("\(sample)\r\nSIZE \(size())\r\n")
if args.first == "--capture", let count = Int(args.last ?? "") {
    output("CAPTURE-READY\r\n")
    var received = [UInt8]()
    while received.count < count {
        var bytes = [UInt8](repeating: 0, count: min(4096, count - received.count))
        let n = Darwin.read(STDIN_FILENO, &bytes, bytes.count)
        if n > 0 { received.append(contentsOf: bytes.prefix(n)) } else if errno != EINTR { exit(2) }
    }
    output("CAPTURE \(received.map { String(format: "%02x", $0) }.joined())\r\n")
    exit(0)
}
func history(_ count: Int) {
    for index in 0..<count { output(String(format: "HISTORY-%05d 中文 é 😀\r\n", index)) }
    output("HISTORY-END\r\n")
}
if args.first == "--burst" { history(Int(args.last ?? "") ?? 10_050) }
output("Keys: u Unicode | h 10050 lines | b paste ON | n paste OFF | q exit\r\n")
output("Ctrl+C, arrows, Tab and input are shown as UTF-8 bytes. Resize reports SIZE.\r\nREADY\r\n")
var oldSize = size()
while true {
    let currentSize = size()
    if currentSize != oldSize { oldSize = currentSize; output("SIZE \(currentSize)\r\n") }
    var descriptor = pollfd(fd: STDIN_FILENO, events: Int16(POLLIN), revents: 0)
    let available = poll(&descriptor, 1, 50)
    guard available > 0 else { continue }
    var bytes = [UInt8](repeating: 0, count: 4096)
    let count = Darwin.read(STDIN_FILENO, &bytes, bytes.count)
    guard count > 0 else { exit(0) }
    let data = Array(bytes.prefix(count))
    if data == [113] { output("\u{1b}[?2004lFIXTURE-EXIT\r\n"); exit(0) }
    if data == [104] { history(10_050); continue }
    if data == [117] { output("\(sample)\r\n"); continue }
    if data == [98] { output("\u{1b}[?2004hPASTE-ON\r\n"); continue }
    if data == [110] { output("\u{1b}[?2004lPASTE-OFF\r\n"); continue }
    output("INPUT \(data.map { String(format: "%02x", $0) }.joined())\r\n")
}
