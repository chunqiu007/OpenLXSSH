import Foundation

/// Fixed management program, not an arbitrary container command or SSH parser.
/// stdout is a bounded private PIPE; never persist or print response output.
public enum MinaManagementPolicy {
    public static let reader = #"""
import json,os,re,stat,sys,time
fds=[]
try:
    assert os.getuid()==10000 and os.getgid()==10000
    mode,attempt=sys.argv[1:]
    assert mode in ('status','responses')
    assert (mode=='status' and attempt=='none') or (mode=='responses' and re.fullmatch(r'[0-9a-f]{24}',attempt))
    directory=os.open('/run',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    fds.append(directory)
    directory=os.open('openlxssh-multiprompt',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=directory)
    fds.append(directory)
    info=os.fstat(directory)
    assert info.st_uid==10000 and info.st_gid==10000 and stat.S_IMODE(info.st_mode)==0o700
    if mode=='responses':
        directory=os.open('attempts',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=directory)
        fds.append(directory)
        info=os.fstat(directory)
        assert info.st_uid==10000 and info.st_gid==10000 and stat.S_IMODE(info.st_mode)==0o700
    name='status.json' if mode=='status' else attempt+'.json'
    fd=os.open(name,os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW,dir_fd=directory)
    fds.append(fd)
    before=os.fstat(fd)
    assert stat.S_ISREG(before.st_mode) and before.st_uid==10000 and before.st_gid==10000 and before.st_nlink==1 and stat.S_IMODE(before.st_mode)==0o600 and 0<before.st_size<=8192
    raw=bytearray()
    while len(raw)<=8192:
        block=os.read(fd,min(4096,8193-len(raw)))
        if not block:break
        raw.extend(block)
    after=os.fstat(fd)
    identity=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
    assert len(raw)==before.st_size and identity(before)==identity(after)
    def unique(pairs):
        value={}
        for key,item in pairs:
            assert key not in value
            value[key]=item
        return value
    value=json.loads(raw,object_pairs_hook=unique)
    if mode=='responses':
        assert set(value)=={'attempt','expires_at','responses','echo'} and value['attempt']==attempt
        assert type(value['expires_at']) is int and time.time()<value['expires_at']<=time.time()+75
        assert type(value['responses']) is list and len(value['responses'])==2 and all(type(v) is str and re.fullmatch(r'[0-9]{10}',v) for v in value['responses'])
        assert type(value['echo']) is list and len(value['echo'])==2 and all(type(v) is bool for v in value['echo']) and value['echo']==[False,True]
    else:
        assert set(value)=={'generated','response_callbacks','zero_response_callbacks','ignored_late_results','sessions','scheduler_queue','pending','outcomes'}
        assert all(type(value[k]) is int and 0<=value[k]<=2147483647 for k in ('generated','response_callbacks','zero_response_callbacks','ignored_late_results','sessions','scheduler_queue'))
        assert value['sessions']<=8 and value['scheduler_queue']<=16 and type(value['pending']) is list and len(value['pending'])<=8
        assert type(value['outcomes']) is dict and set(value['outcomes'])<={'replaced','setup-failed','rejected','accepted','approved','expired','session-closed','shutdown'} and all(type(v) is int and 0<=v<=2147483647 for v in value['outcomes'].values())
        for item in value['pending']:
            assert set(item)=={'attempt','scenario','prompt_count','responded','expires_at'} and re.fullmatch(r'[0-9a-f]{24}',item['attempt'])
            assert item['scenario'] in ('two','zero-accept','zero-reject','approval','reject','cancel','timeout') and type(item['prompt_count']) is int and item['prompt_count']==(2 if item['scenario']=='two' else 0) and type(item['responded']) is bool and type(item['expires_at']) is int
    encoded=json.dumps(value,separators=(',',':')).encode()
    assert len(encoded)<=8192
    view=memoryview(encoded)
    while view:
        count=os.write(1,view)
        assert count>0
        view=view[count:]
except Exception:
    raise SystemExit(1)
finally:
    for fd in reversed(fds):os.close(fd)
"""#

    public static func readerArguments(contract: MinaContract, attempt: String?) throws -> [String] {
        if let attempt, !Contract.hex(attempt, count: 24) { throw MinaError.invalidResponses }
        return ["--host", contract.endpoint, "exec", "--user", "10000:10000", contract.containerID,
                "/usr/bin/python3", "-c", reader, attempt == nil ? "status" : "responses", attempt ?? "none"]
    }
    public static let policyReader = #"""
import json,os,stat,sys
fds=[]
try:
    assert os.getuid()==10000 and os.getgid()==10000 and len(sys.argv)==1
    directory=os.open('/run',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    fds.append(directory)
    directory=os.open('openlxssh-multiprompt',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=directory)
    fds.append(directory)
    info=os.fstat(directory)
    assert info.st_uid==10000 and info.st_gid==10000 and stat.S_IMODE(info.st_mode)==0o700
    fd=os.open('scenario',os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW,dir_fd=directory)
    fds.append(fd)
    before=os.fstat(fd)
    assert stat.S_ISREG(before.st_mode) and before.st_uid==10000 and before.st_gid==10000 and before.st_nlink==1 and stat.S_IMODE(before.st_mode)==0o600 and 0<before.st_size<=128
    raw=os.read(fd,129)
    after=os.fstat(fd)
    identity=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
    assert len(raw)==before.st_size and identity(before)==identity(after)
    scenario,delay=raw.decode('ascii').strip().split(' ')
    assert scenario in ('approval','reject','cancel') and delay=='8'
    encoded=json.dumps({'scenario':scenario,'delay':8},separators=(',',':')).encode()
    assert os.write(1,encoded)==len(encoded)
except Exception:
    raise SystemExit(1)
finally:
    for fd in reversed(fds):os.close(fd)
"""#
    public static func policyArguments(contract: MinaContract) -> [String] {
        ["--host", contract.endpoint, "exec", "--user", "10000:10000", contract.containerID, "/usr/bin/python3", "-c", policyReader]
    }
    public static func validatePolicy(_ data: Data, testCase: MinaCase) throws {
        let object = try MinaJSON.object(data, keys: ["scenario", "delay"])
        guard testCase.isAsync, object["scenario"] as? String == testCase.scenario,
              object["delay"] as? Int == Int(MinaContract.providerDelaySeconds) else { throw MinaError.statusMismatch }
    }
    public static func validateContainer(_ data: Data, contract: MinaContract) throws {
        guard let items = try JSONSerialization.jsonObject(with: data) as? [[String: Any]], items.count == 1 else { throw MinaError.provenanceMismatch }
        let item = items[0]
        guard item["Id"] as? String == contract.containerID, item["Image"] as? String == contract.imageID,
              let state = item["State"] as? [String: Any], state["Running"] as? Bool == true,
              let health = state["Health"] as? [String: Any], health["Status"] as? String == "healthy",
              let config = item["Config"] as? [String: Any], config["User"] as? String == "10000:10000",
              config["Image"] as? String == "openlxssh-auth-mina-fixture:2.20.0-arm64",
              let labels = config["Labels"] as? [String: String],
              labels["org.openlxssh.fixture"] == contract.fixtureLabel,
              labels["com.docker.compose.project"] == contract.project, labels["com.docker.compose.service"] == "multiprompt",
              labels["org.openlxssh.fixture.source"] == contract.sourceSHA256, labels["org.openlxssh.fixture.base"] == contract.baseImage,
              let host = item["HostConfig"] as? [String: Any], host["ReadonlyRootfs"] as? Bool == true,
              host["Privileged"] as? Bool == false, host["Init"] as? Bool == true, host["CapDrop"] as? [String] == ["ALL"],
              host["Memory"] as? Int == 536870912, host["MemorySwap"] as? Int == 536870912,
              host["NanoCpus"] as? Int == 500000000, host["PidsLimit"] as? Int == 128,
              let logging = host["LogConfig"] as? [String: Any], logging["Type"] as? String == "none",
              (host["SecurityOpt"] as? [String] == ["no-new-privileges:true"] || host["SecurityOpt"] as? [String] == ["no-new-privileges"]),
              let ports = host["PortBindings"] as? [String: [[String: String]]],
              ports == ["2222/tcp": [["HostIp": "127.0.0.1", "HostPort": "22225"]]],
              let network = item["NetworkSettings"] as? [String: Any], let networks = network["Networks"] as? [String: [String: Any]],
              networks.count == 1, networks[contract.project + "_multiprompt-private"]?["NetworkID"] as? String == contract.networkID,
              let mounts = item["Mounts"] as? [Any], mounts.isEmpty else { throw MinaError.provenanceMismatch }
        guard let effective = network["Ports"] as? [String: Any], Set(effective.keys) == ["2222/tcp"],
              let published = effective["2222/tcp"] as? [[String: String]],
              published.isEmpty || published == [["HostIp": "127.0.0.1", "HostPort": "22225"]],
              host["Tmpfs"] as? [String: String] == [
                "/run/openlxssh-multiprompt": "rw,nosuid,nodev,noexec,size=16m,mode=0700,uid=10000,gid=10000",
                "/tmp": "rw,nosuid,nodev,noexec,size=32m,mode=1777"] else { throw MinaError.provenanceMismatch }
        for key in ["CapAdd", "Binds", "Devices", "DeviceRequests", "VolumesFrom"] {
            if let value = host[key], !(value is NSNull), (value as? [Any])?.isEmpty != true { throw MinaError.provenanceMismatch }
        }
        guard host["PidMode"] as? String == "", ["", "private"].contains(host["IpcMode"] as? String ?? "invalid"),
              host["NetworkMode"] as? String == contract.project + "_multiprompt-private",
              let restart = host["RestartPolicy"] as? [String: Any], restart["Name"] as? String == "no" else { throw MinaError.provenanceMismatch }
    }
    public static func validateImage(_ data: Data, contract: MinaContract) throws {
        guard let items = try JSONSerialization.jsonObject(with: data) as? [[String: Any]], items.count == 1,
              items[0]["Id"] as? String == contract.imageID, items[0]["Architecture"] as? String == "arm64", items[0]["Os"] as? String == "linux",
              let config = items[0]["Config"] as? [String: Any], let labels = config["Labels"] as? [String: String],
              labels["org.openlxssh.fixture"] == contract.fixtureLabel, labels["com.docker.compose.project"] == contract.project,
              labels["org.openlxssh.fixture.source"] == contract.sourceSHA256, labels["org.openlxssh.fixture.base"] == contract.baseImage else { throw MinaError.provenanceMismatch }
    }
    public static func validateNetwork(_ data: Data, contract: MinaContract) throws {
        guard let items = try JSONSerialization.jsonObject(with: data) as? [[String: Any]], items.count == 1,
              items[0]["Id"] as? String == contract.networkID, items[0]["Internal"] as? Bool == true,
              items[0]["Driver"] as? String == "bridge", let labels = items[0]["Labels"] as? [String: String],
              labels["org.openlxssh.fixture"] == contract.fixtureLabel, labels["com.docker.compose.project"] == contract.project,
              let containers = items[0]["Containers"] as? [String: Any], Set(containers.keys) == [contract.containerID] else { throw MinaError.provenanceMismatch }
    }
}
