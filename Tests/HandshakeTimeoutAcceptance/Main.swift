import Darwin
import Foundation
import RealIntegrationCore

@main enum Main {
    static func main()async {
        do{
            let options=try TimeoutOptions.parse(Array(CommandLine.arguments.dropFirst()))
            if options.action == .help{print(TimeoutOptions.help);return}
            if options.action == .validate{print("Syntax valid only; no files, sockets, credentials, children or acceptance.");return}
            guard let path=options.path else{throw TimeoutFailure.arguments}
            _=try TimeoutContract.path(path,ownRoot:BuildLocation.ownRoot)
            try PrivateInput.checkDirectory(BuildLocation.ownRoot+"/.runtime")
            let data=try PrivateInput.read(path,limit:4096)
            guard let object=try JSONSerialization.jsonObject(with:data) as? [String:Any],Set(object.keys)==TimeoutContract.keys else{throw TimeoutFailure.contract}
            let contract=try JSONDecoder().decode(TimeoutContract.self,from:data)
            try contract.validate(path:path,ownRoot:BuildLocation.ownRoot)
            _=umask(0o077)
            exit(try await TimeoutRun.execute(contract,path:path))
        }catch{fputs("Handshake timeout refused: "+((error as? TimeoutFailure)?.rawValue ?? "private-input-or-production-error")+". No wire or private details.\n",stderr);exit(2)}
    }
}
