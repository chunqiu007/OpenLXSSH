import Darwin
import Foundation
import RealIntegrationCore

@main enum Main {
    static func main()async {
        do {
            let options=try AuthOptions.parse(Array(CommandLine.arguments.dropFirst()))
            if options.action == .help {print(AuthOptions.help);return}
            if options.action == .validate {print("Syntax only: no files, child, credentials or network.");return}
            guard let path=options.path else {throw AuthFailureError.arguments};_=umask(0o077)
            if options.action == .prepare {
                guard let scenario=options.testCase else {throw AuthFailureError.arguments}
                let input=try await Task.detached{try AuthPublic.load(path,now:Date().timeIntervalSince1970,fresh:true)}.value
                let runtime=BuildLocation.ownRoot+"/.runtime"
                if mkdir(runtime,0o700) != 0 && errno != EEXIST {throw AuthFailureError.contract};try PrivateInput.checkDirectory(runtime)
                let id=UUID().uuidString.lowercased(),directory=runtime+"/auth-"+id
                guard mkdir(directory,0o700)==0 else {throw AuthFailureError.contract}
                let contract=AuthContract(schema:1,id:id,scenario:scenario,generation:path,project:AuthFixed.project,container:AuthFixed.container,image:AuthFixed.image,base:AuthFixed.base,
                    fingerprint:AuthFixed.fingerprint,collectedAt:input.collectedAt,preparedAt:Date().timeIntervalSince1970,publicHashes:input.hashes,replacementStep:scenario == .knownHostMismatch ? AuthFixed.replacementStep:"not-applicable")
                try contract.validate(path:directory+"/case.json",now:Date().timeIntervalSince1970)
                if scenario == .knownHostMismatch {try makePublicMismatchKey(directory:directory)}
                try authJSON(contract,directory:directory,name:"case.json")
                print("Prepared public-only case: "+directory+"/case.json");return
            }
            _=try AuthContract.path(path);try PrivateInput.checkDirectory(BuildLocation.ownRoot+"/.runtime")
            let data=try PrivateInput.read(path,limit:8192);_=try authObject(data,keys:AuthContract.keys)
            let contract=try JSONDecoder().decode(AuthContract.self,from:data)
            try contract.validate(path:path,now:Date().timeIntervalSince1970)
            let input=try await Task.detached{try AuthPublic.load(contract.generation,now:Date().timeIntervalSince1970,fresh:false)}.value
            try contract.check(input)
            let directory=String(path.dropLast("/case.json".count))
            if options.action == .runNegative {exit(try await AuthRun.negative(contract,input:input,directory:directory))}
            exit(try await AuthRun.replacement(contract,input:input,directory:directory))
        }catch {
            fputs("Authentication failure case refused: "+((error as? AuthFailureError)?.rawValue ?? "private-gate-or-production-error")+". No secret details.\n",stderr);exit(2)
        }
    }
}
