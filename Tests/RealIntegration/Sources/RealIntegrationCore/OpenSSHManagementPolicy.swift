import Foundation

public enum OpenSSHManagementPolicy {
    public static let reader = #"""
import json,os,re,stat,sys,time
fds=[]
try:
    assert os.getuid()==0 and os.getgid()==0
    action,session,index=sys.argv[1:]
    assert action in ('policy','response','session-state')
    assert (action=='policy' and session=='none' and index=='none') or (action!='policy' and re.fullmatch(r'[0-9a-f]{24}',session) and index in ('0','1','2','none'))
    directory=os.open('/run',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);fds.append(directory)
    directory=os.open('openlxssh-fixture',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=directory);fds.append(directory)
    info=os.fstat(directory);assert info.st_uid==0 and info.st_gid==0 and stat.S_IMODE(info.st_mode)==0o755
    if action!='policy':
        directory=os.open('sessions',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=directory);fds.append(directory)
        info=os.fstat(directory);assert info.st_uid==0 and info.st_gid==0 and stat.S_IMODE(info.st_mode)==0o700
    name='config.json' if action=='policy' else session+'.json'
    try:fd=os.open(name,os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW,dir_fd=directory)
    except FileNotFoundError:
        assert action=='session-state'
        os.write(1,b'{"present":false}')
        raise SystemExit(0)
    fds.append(fd);before=os.fstat(fd)
    assert stat.S_ISREG(before.st_mode) and before.st_uid==0 and before.st_gid==0 and before.st_nlink==1 and stat.S_IMODE(before.st_mode)==0o600 and 0<before.st_size<=4096
    raw=bytearray()
    while len(raw)<=4096:
        part=os.read(fd,min(2048,4097-len(raw)))
        if not part:break
        raw.extend(part)
    after=os.fstat(fd)
    identity=lambda x:(x.st_dev,x.st_ino,x.st_mode,x.st_uid,x.st_gid,x.st_nlink,x.st_size,x.st_mtime_ns,x.st_ctime_ns)
    assert len(raw)==before.st_size and identity(before)==identity(after)
    def unique(pairs):
        result={}
        for key,value in pairs:
            assert key not in result
            result[key]=value
        return result
    value=json.loads(raw,object_pairs_hook=unique)
    if action=='policy':
        assert set(value)=={'version','mode','scenario','delay'} and type(value['version']) is int and value['version']==1
        assert value['mode'] in ('keyonly','passwordonly','key-kbd','password-kbd') and value['scenario']=='multi' and type(value['delay']) is int and 1<=value['delay']<=60
        output=value
    elif action=='session-state':
        output={'present':True}
    else:
        assert index in ('0','1','2') and set(value)=={'session','expires_at','scenario','responses'}
        assert value['session']==session and value['scenario']=='multi' and type(value['expires_at']) in (int,float) and time.time()<value['expires_at']<=time.time()+75
        assert type(value['responses']) is list and len(value['responses'])==3 and all(type(x) is str and re.fullmatch(r'[0-9]{8}',x) for x in value['responses'])
        output={'session':session,'index':int(index),'expires_at':value['expires_at'],'response':value['responses'][int(index)]}
    encoded=json.dumps(output,separators=(',',':')).encode();assert len(encoded)<=4096
    view=memoryview(encoded)
    while view:
        n=os.write(1,view);assert n>0;view=view[n:]
except Exception:
    raise SystemExit(1)
finally:
    for fd in reversed(fds):os.close(fd)
"""#
    public static func arguments(contract: OpenSSHContract, session: String?, index: Int?, stateOnly: Bool = false) throws -> [String] {
        if let session { guard Contract.hex(session, count: 24) else { throw OpenSSHError.wrongRound } }
        if let index { guard (0..<3).contains(index), session != nil, !stateOnly else { throw OpenSSHError.wrongRound } }
        guard (session == nil && index == nil && !stateOnly) || (session != nil && (stateOnly || index != nil)) else { throw OpenSSHError.wrongRound }
        return ["--host", contract.endpoint, "exec", "--user", "0:0", contract.containerID, "/usr/bin/python3", "-c", reader,
                session == nil ? "policy" : (stateOnly ? "session-state" : "response"), session ?? "none", index.map(String.init) ?? "none"]
    }
    public static func validatePolicy(_ data: Data, contract: OpenSSHContract) throws {
        let value = try MinaJSON.object(data, keys: ["version", "mode", "scenario", "delay"])
        guard value["version"] as? Int == 1, value["mode"] as? String == contract.service.rawValue, value["scenario"] as? String == "multi",
              let delay = value["delay"] as? Int, (1...60).contains(delay) else { throw OpenSSHError.provenanceMismatch }
    }
    public static func validateContainer(_ data: Data, contract: OpenSSHContract) throws {
        guard let objects = try JSONSerialization.jsonObject(with: data) as? [[String: Any]], objects.count == 1 else { throw OpenSSHError.provenanceMismatch }
        let item = objects[0]
        guard item["Id"] as? String == contract.containerID, item["Image"] as? String == contract.imageID,
              let config = item["Config"] as? [String: Any], let labels = config["Labels"] as? [String: String],
              labels["org.openlxssh.fixture"] == "env-fixture-a", labels["com.docker.compose.project"] == contract.project,
              labels["com.docker.compose.service"] == contract.service.rawValue,
              let state = item["State"] as? [String: Any], state["Running"] as? Bool == true,
              let health = state["Health"] as? [String: Any], health["Status"] as? String == "healthy",
              let host = item["HostConfig"] as? [String: Any], host["ReadonlyRootfs"] as? Bool == true, host["Privileged"] as? Bool == false,
              let log = host["LogConfig"] as? [String: Any], log["Type"] as? String == "none",
              let ports = host["PortBindings"] as? [String: [[String: String]]], ports == ["2222/tcp": [["HostIp": "127.0.0.1", "HostPort": String(contract.port)]]],
              let networking = item["NetworkSettings"] as? [String: Any], let networks = networking["Networks"] as? [String: [String: Any]],
              networks.count == 1, networks.values.first?["NetworkID"] as? String == contract.networkID,
              let mounts = item["Mounts"] as? [[String: Any]], mounts.allSatisfy({ $0["Type"] as? String != "bind" }) else { throw OpenSSHError.provenanceMismatch }
    }
    public static func validateImage(_ data: Data, contract: OpenSSHContract) throws {
        guard let objects = try JSONSerialization.jsonObject(with: data) as? [[String: Any]], objects.count == 1,
              objects[0]["Id"] as? String == contract.imageID, objects[0]["Architecture"] as? String == "arm64", objects[0]["Os"] as? String == "linux",
              let config = objects[0]["Config"] as? [String: Any], let labels = config["Labels"] as? [String: String],
              labels["org.openlxssh.fixture"] == "env-fixture-a", labels["org.openlxssh.fixture.base"] == contract.baseImage else { throw OpenSSHError.provenanceMismatch }
    }
    public static func validateNetwork(_ data: Data, contract: OpenSSHContract) throws {
        guard let objects = try JSONSerialization.jsonObject(with: data) as? [[String: Any]], objects.count == 1,
              objects[0]["Id"] as? String == contract.networkID, objects[0]["Internal"] as? Bool == true, objects[0]["Driver"] as? String == "bridge",
              let labels = objects[0]["Labels"] as? [String: String], labels["org.openlxssh.fixture"] == "env-fixture-a",
              labels["com.docker.compose.project"] == contract.project,
              let containers = objects[0]["Containers"] as? [String: Any], containers[contract.containerID] != nil else { throw OpenSSHError.provenanceMismatch }
    }
}
