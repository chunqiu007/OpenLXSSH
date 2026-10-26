import Darwin
import Foundation
import OpenLXSSHFiles
import RealIntegrationCore

@main enum DisconnectMain {
    @MainActor static func main() async {
        do {
            let options = try DisconnectOptions.parse(Array(CommandLine.arguments.dropFirst()))
            if options.action == .help { print(DisconnectOptions.help); return }
            if options.action == .validate { print("Disconnect case syntax only; no file/network I/O."); return }
            guard let path = options.path else { throw DisconnectError.arguments }
            _ = umask(0o077)
            if options.action == .prepare {
                let material = try PublicMaterial.load(directory: path, fixtureRoot: BuildLocation.fixtureRoot, now: Date().timeIntervalSince1970, fresh: true)
                let runtime = BuildLocation.ownRoot + "/.runtime"
                if mkdir(runtime, 0o700) != 0 && errno != EEXIST { throw DisconnectError.contract }
                try PrivateInput.checkDirectory(runtime)
                let contract = DisconnectContract.make(generation: path, input: material, now: Date().timeIntervalSince1970)
                let directory = runtime + "/disconnect-" + contract.id
                try require(mkdir(directory, 0o700) == 0); try PrivateInput.checkDirectory(directory)
                let contractPath = directory + "/case.json"
                try contract.validate(path: contractPath, ownRoot: BuildLocation.ownRoot, fixtureRoot: BuildLocation.fixtureRoot,
                    now: Date().timeIntervalSince1970, builtAt: BuildLocation.offlinePreparedAt)
                try writeDisconnectJSON(contract, directory: directory, name: "case.json")
                print("Prepared public metadata only. Disconnect case: " + contractPath); return
            }
            _ = try DisconnectContract.validatePath(path, ownRoot: BuildLocation.ownRoot)
            try PrivateInput.checkDirectory(BuildLocation.ownRoot + "/.runtime")
            let bytes = try PrivateInput.read(path, limit: 8192)
            _ = try object(bytes, keys: ["schema", "id", "generation", "provenanceSHA256", "knownHostsSHA256", "fingerprintSHA256", "packagesSHA256",
                "collectedAt", "preparedAt", "project", "container", "base", "image", "fingerprint"])
            let contract = try JSONDecoder().decode(DisconnectContract.self, from: bytes)
            try contract.validate(path: path, ownRoot: BuildLocation.ownRoot, fixtureRoot: BuildLocation.fixtureRoot,
                now: Date().timeIntervalSince1970, builtAt: BuildLocation.offlinePreparedAt)
            let input = try PublicMaterial.load(directory: contract.generation, fixtureRoot: BuildLocation.fixtureRoot,
                now: Date().timeIntervalSince1970, fresh: false)
            try contract.check(input)
            let directory = String(path.dropLast("/case.json".count))
            if options.action == .upload { exit(try await DisconnectUpload.run(contract: contract, input: input, directory: directory)) }
            exit(try await DisconnectVerify.run(contract: contract, input: input, directory: directory, cleanup: options.cleanup))
        } catch {
            let safe = (error as? DisconnectError)?.rawValue ?? (error as? GateError)?.rawValue ?? (error as? FileServiceError)?.kind.rawValue ?? "private-input-refused"
            fputs("Disconnect case refused/failed: " + safe + ". No secret details.\n", stderr); exit(2)
        }
    }
}
