import Darwin
import Foundation
import RealIntegrationCore

@main enum Main {
    @MainActor static func main() async {
        do {
            let args=try DiskOptions.parse(Array(CommandLine.arguments.dropFirst()))
            if args.action == .help { print(DiskOptions.help);return }
            if args.action == .validate { print("Syntax only; no filesystem, child, credential or network I/O.");return }
            guard let path=args.path else { throw DiskError.arguments }
            _=umask(0o077)
            if args.action == .prepare {
                let input=try PublicMaterial.load(directory:path,fixtureRoot:BuildLocation.fixtureRoot,now:Date().timeIntervalSince1970,fresh:true)
                let runtime=BuildLocation.ownRoot+"/.runtime"
                if mkdir(runtime,0o700) != 0 && errno != EEXIST { throw DiskError.contract }
                try PrivateInput.checkDirectory(runtime)
                let contract=DiskContract.make(generation:path,input:input,now:Date().timeIntervalSince1970)
                let directory=runtime+"/enospc-"+contract.id
                guard mkdir(directory,0o700)==0 else { throw DiskError.contract }
                try contract.validate(path:directory+"/case.json",now:Date().timeIntervalSince1970)
                try diskJSON(contract,directory:directory,name:"case.json")
                print("Prepared public metadata only: "+directory+"/case.json");return
            }
            _=try DiskContract.validatePath(path,ownRoot:BuildLocation.ownRoot)
            try PrivateInput.checkDirectory(BuildLocation.ownRoot+"/.runtime")
            let data=try PrivateInput.read(path,limit:8192)
            _=try object(data,keys:["schema","id","generation","provenanceSHA256","knownHostsSHA256","fingerprintSHA256","packagesSHA256","collectedAt","preparedAt","project","container","base","image","fingerprint"])
            let contract=try JSONDecoder().decode(DiskContract.self,from:data)
            try contract.validate(path:path,now:Date().timeIntervalSince1970)
            let input=try PublicMaterial.load(directory:contract.generation,fixtureRoot:BuildLocation.fixtureRoot,now:Date().timeIntervalSince1970,fresh:false)
            try contract.check(input)
            let directory=String(path.dropLast("/case.json".count))
            exit(try await DiskRun.run(contract:contract,input:input,directory:directory,path:path))
        } catch {
            fputs("Disk-full case refused: "+((error as? DiskError)?.rawValue ?? "private-input-or-production-error")+". No secret details.\n",stderr)
            exit(2)
        }
    }
}
