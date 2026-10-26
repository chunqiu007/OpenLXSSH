import Darwin
import Foundation
import RealIntegrationCore

@main enum Main {
    @MainActor static func main() async {
        do {
            let args = try Arguments.parse(Array(CommandLine.arguments.dropFirst()))
            if args.action == .help { print(Arguments.help); return }
            if args.action == .validate { print("Syntax valid only; no file/network I/O and no acceptance result."); return }
            guard let path = args.path else { throw GateError.arguments }
            _ = umask(0o077)
            if args.action == .prepare {
                // No secret key/password read and no network, Docker or data generation.
                let publicInput = try PublicMaterial.load(directory: path, fixtureRoot: BuildLocation.fixtureRoot,
                    now: Date().timeIntervalSince1970, fresh: true)
                let runtime = BuildLocation.ownRoot + "/.runtime"
                if mkdir(runtime, 0o700) != 0 && errno != EEXIST { throw GateError.contract }
                try PrivateInput.checkDirectory(runtime)
                let id = UUID().uuidString.lowercased(), directory = runtime + "/campaign-" + id
                try require(mkdir(directory, 0o700) == 0); try PrivateInput.checkDirectory(directory)
                let campaign = Campaign(schema: 1, id: id, generation: path, provenanceSHA256: publicInput.provenanceSHA256,
                    knownHostsSHA256: publicInput.knownHostsSHA256, fingerprintSHA256: publicInput.fingerprintSHA256,
                    packagesSHA256: publicInput.packagesSHA256, collectedAt: publicInput.collectedAt,
                    preparedAt: Date().timeIntervalSince1970, project: Fixed.project, container: Fixed.container,
                    base: Fixed.base, image: Fixed.image, fingerprint: Fixed.fingerprint)
                try campaign.validate(path: directory + "/campaign.json", ownRoot: BuildLocation.ownRoot,
                    fixtureRoot: BuildLocation.fixtureRoot, now: Date().timeIntervalSince1970)
                try PrivateInput.writeExclusive(JSONEncoder().encode(campaign), to: directory + "/campaign.json")
                print("Prepared public metadata only. Campaign: " + directory + "/campaign.json")
                return
            }
            // Refuse arbitrary paths BEFORE reading. Exact UUID, no search/latest/fallback.
            let prefix = BuildLocation.ownRoot + "/.runtime/campaign-", suffix = "/campaign.json"
            guard path.hasPrefix(prefix), path.hasSuffix(suffix),
                  let id = UUID(uuidString: String(path.dropFirst(prefix.count).dropLast(suffix.count))),
                  path == prefix + id.uuidString.lowercased() + suffix else { throw GateError.contract }
            try PrivateInput.checkDirectory(BuildLocation.ownRoot + "/.runtime")
            let bytes = try PrivateInput.read(path, limit: 8192)
            _ = try object(bytes, keys: ["schema", "id", "generation", "provenanceSHA256", "knownHostsSHA256", "fingerprintSHA256", "packagesSHA256",
                "collectedAt", "preparedAt", "project", "container", "base", "image", "fingerprint"])
            let campaign = try JSONDecoder().decode(Campaign.self, from: bytes)
            try campaign.validate(path: path, ownRoot: BuildLocation.ownRoot, fixtureRoot: BuildLocation.fixtureRoot, now: Date().timeIntervalSince1970)
            try require(campaign.collectedAt >= BuildLocation.offlinePreparedAt, .provenance)
            let publicInput = try PublicMaterial.load(directory: campaign.generation, fixtureRoot: BuildLocation.fixtureRoot,
                now: Date().timeIntervalSince1970, fresh: false)
            try publicInput.matches(campaign)
            let run = try CampaignRun(contract: campaign, path: path, input: publicInput, fixtureRoot: BuildLocation.fixtureRoot)
            let monitor = run.monitor
            let sampling = Task {
                while !Task.isCancelled {
                    await monitor.sample()
                    do { try await Task.sleep(for: .milliseconds(250)) } catch { return }
                }
            }
            let watchdog = Task { @MainActor in
                do { try await Task.sleep(for: .seconds(Fixed.maximumSeconds)) } catch { return }
                run.requestStop()
            }
            var failure: Error?
            do { try await run.execute() } catch { failure = error }
            watchdog.cancel(); await watchdog.value
            sampling.cancel(); await sampling.value
            exit(try await run.finish(failure: failure))
        } catch {
            let code = (error as? GateError)?.rawValue ?? "private-input-or-build-binding-refused"
            fputs("Remote acceptance refused: " + code + ". No secret details emitted.\n", stderr); exit(2)
        }
    }
}
