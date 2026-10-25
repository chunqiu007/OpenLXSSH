import Darwin
import Foundation

/// Fixed no-network fixture code. Host strings are passed only as data arguments, never interpolated.
public enum ProbeFixture {
    public static let executable = "/usr/bin/python3"
    public static let code = #"""
import errno, fcntl, json, os, signal, struct, sys, termios, time, tty

def write_all(data):
    while data:
        n = os.write(1, data)
        data = data[n:]

def window():
    return list(struct.unpack('HHHH', fcntl.ioctl(0, termios.TIOCGWINSZ, b'\0' * 8))[:2])

mode = sys.argv[1]
if mode == 'argv':
    write_all(('ARGV:' + json.dumps(sys.argv[2:]) + '\n').encode())
elif mode == 'io':
    tty.setraw(0)
    signal.signal(signal.SIGWINCH, lambda *_: write_all(('WINCH:' + json.dumps(window()) + '\n').encode()))
    write_all(('READY:' + json.dumps({'tty': os.isatty(0), 'pgrp': os.getpgrp(),
                                     'foreground': os.tcgetpgrp(0), 'window': window()}) + '\n').encode())
    data = b''
    while len(data) < 256:
        chunk = os.read(0, 256 - len(data))
        if not chunk:
            raise RuntimeError('unexpected input EOF')
        data += chunk
    write_all(b'BYTES:' + data.hex().encode() + b'\n')
elif mode == 'eof-first':
    os.close(0)
    os.close(1)
    os.close(2)
    time.sleep(20)
elif mode == 'sleep':
    write_all(b'READY\n')
    time.sleep(20)
elif mode == 'ignore-term':
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    write_all(b'READY\n')
    time.sleep(20)
elif mode == 'burst':
    tty.setraw(1)
    write_all(bytes(range(256)) * int(sys.argv[2]))
elif mode == 'fd':
    name = sys.argv[2]
    candidate = int(sys.argv[3])
    try:
        inherited = fcntl.fcntl(candidate, fcntl.F_GETPATH).split(b'\0')[0].decode() == name
    except OSError:
        inherited = False
    write_all(('INHERITED:' + str(inherited) + '\n').encode())
elif mode == 'exit':
    sys.exit(int(sys.argv[2]))
else:
    raise RuntimeError('unknown fixture mode')
"""#

    public static func configuration(
        _ mode: String, arguments: [String] = [], timeout: Duration = .seconds(3),
        maximumOutputBytes: Int = 1_048_576
    ) throws -> PTYProbeSession.Configuration {
        try .init(
            executable: executable, arguments: ["-I", "-c", code, mode] + arguments,
            timeout: timeout, maximumOutputBytes: maximumOutputBytes
        )
    }

    public static let edgeArguments = [
        "host with spaces", "line\nbreak", "-oProxyCommand=not-a-command", "quote'\"",
        "2001:db8::1", "[::1]", "", "$(not-a-command); > /not-a-real-output", "中文-host"
    ]
}

public enum ProbeCheckError: Error {
    case outputNotObserved
    case failed(String)
}

public func waitForOutput(_ marker: Data, from session: PTYProbeSession, timeout: Duration = .seconds(2)) async throws {
    let deadline = ContinuousClock.now + timeout
    while ContinuousClock.now < deadline {
        if await session.capturedOutput().range(of: marker) != nil { return }
        try await Task.sleep(for: .milliseconds(5))
    }
    _ = await session.close()
    throw ProbeCheckError.outputNotObserved
}

/// Reproducible CLI scenario, also used by XCTest without launching anything over the network.
public func runLocalSmoke(snapshotHold: Duration = .zero) async throws -> [String] {
    var summary: [String] = []
    let arguments = ProbeFixture.edgeArguments
    let argvSession = PTYProbeSession(configuration: try ProbeFixture.configuration("argv", arguments: arguments))
    try await argvSession.start()
    let argvResult = await argvSession.wait()
    let argvText = String(decoding: argvResult.output, as: UTF8.self)
    guard let range = argvText.range(of: "ARGV:"),
          let jsonLine = argvText[range.upperBound...].split(whereSeparator: { $0 == "\r" || $0 == "\n" }).first,
          let observed = try JSONSerialization.jsonObject(with: Data(jsonLine.utf8)) as? [String],
          observed == arguments, argvResult.exitCode == 0, argvResult.childReaped, argvResult.masterClosed else {
        throw ProbeCheckError.failed("argument vector round-trip")
    }
    summary.append("argv: \(observed.count) exact boundary values, no shell/network")

    let io = PTYProbeSession(configuration: try ProbeFixture.configuration("io"))
    try await io.start()
    try await waitForOutput(Data("READY:".utf8), from: io)
    let readyText = String(decoding: await io.capturedOutput(), as: UTF8.self)
    guard let readyStart = readyText.range(of: "READY:"),
          let readyLine = readyText[readyStart.upperBound...].split(whereSeparator: { $0 == "\r" || $0 == "\n" }).first,
          let ready = try JSONSerialization.jsonObject(with: Data(readyLine.utf8)) as? [String: Any],
          ready["tty"] as? Bool == true,
          let foreground = ready["foreground"] as? Int,
          foreground == ready["pgrp"] as? Int,
          ready["window"] as? [Int] == [24, 80] else {
        _ = await io.close()
        throw ProbeCheckError.failed("controlling terminal or initial window")
    }
    let size = try WindowSize(rows: 41, columns: 123)
    guard try await io.resize(size) == size else {
        _ = await io.close()
        throw ProbeCheckError.failed("window readback")
    }
    try await waitForOutput(Data("WINCH:[41, 123]".utf8), from: io)
    try await io.send(Data((0..<128).map(UInt8.init)))
    try await io.send(Data((128..<256).map(UInt8.init)))
    let ioResult = await io.wait()
    let expected = Data((0..<256).map(UInt8.init)).map { String(format: "%02x", $0) }.joined()
    guard String(decoding: ioResult.output, as: UTF8.self).contains("BYTES:" + expected),
          ioResult.exitCode == 0, ioResult.reachedEOF, ioResult.childReaped else {
        throw ProbeCheckError.failed("PTY I/O order or EOF")
    }
    summary.append("pty: 256 ordered input bytes, controlling tty, window=41x123, SIGWINCH, EOF")

    let ssh = PTYProbeSession(configuration: try .init(
        executable: SSHArgumentVector.executable,
        arguments: SSHArgumentVector.inspectionArguments(host: "2001:db8::1")
    ))
    try await ssh.start()
    let sshResult = await ssh.wait()
    guard sshResult.exitCode == 0,
          String(decoding: sshResult.output, as: UTF8.self).contains("hostname 2001:db8::1") else {
        throw ProbeCheckError.failed("OpenSSH -G")
    }
    summary.append("openssh: /usr/bin/ssh -G only; no connection/authentication")

    let cancel = PTYProbeSession(configuration: try ProbeFixture.configuration("ignore-term", timeout: .seconds(15)))
    try await cancel.start()
    try await waitForOutput(Data("READY".utf8), from: cancel)
    let cancelResources = await cancel.snapshot()
    let snapshotChild = cancelResources.pid ?? 0
    let snapshotMaster = cancelResources.masterFD ?? -1
    if snapshotHold > .zero {
        print("SNAPSHOT parent=\(getpid()) child=\(snapshotChild) master=\(snapshotMaster) slave=\(cancelResources.slaveName ?? "none") tasks=\(cancelResources.ownedAsyncTasks)")
        fflush(stdout)
        try await Task.sleep(for: snapshotHold)
    }
    let cancelled = await cancel.cancel()
    let closedAgain = await cancel.close()
    guard cancelled == closedAgain, cancelled.escalatedToKill, cancelled.signal == SIGKILL,
          cancelled.childReaped, cancelled.masterClosed, cancelled.ownedAsyncTasks == 0 else {
        throw ProbeCheckError.failed("cancel escalation or idempotent close")
    }
    if snapshotHold > .zero {
        print("CLEANED parent=\(getpid()) child=\(snapshotChild) master=\(snapshotMaster) tasks=\(cancelled.ownedAsyncTasks)")
        fflush(stdout)
        try await Task.sleep(for: .seconds(3))
    }
    summary.append("cancel: SIGTERM→SIGKILL, child reaped, PTY closed, tasks=0, repeated close stable")
    return summary
}
