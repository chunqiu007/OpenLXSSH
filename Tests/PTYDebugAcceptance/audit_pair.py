#!/usr/bin/env python3
"""Fixed A/B AUDIT_WRITE pair. Default/help/plan inert; live requires primary release."""
import argparse,hashlib,importlib.util,json,os,re,stat,sys,threading,time,uuid
from pathlib import Path
HERE=Path(__file__).absolute().parent
FIXTURE=HERE.parent/'IntegrationEnvironment'
DOCKER='/Applications/Docker.app/Contents/Resources/bin/docker'
ENDPOINT='unix:///Users/liuwenshuo/.docker/run/docker.sock'
IMAGE='sha256:7f633d33bf5af2fbee137385eba3e036ef7bbbcf18fe423d99b25be12d12a363'
BASE='docker.io/library/ubuntu:24.04@sha256:18b33ff3829707f31ada654a963b9ee35f2e6f0241b964bd17a22a9b330cb63d'
ROOT_IDS=('2db5bbb3cb75a3253d9b02af5ca52cbdc8095230464f82c18d37eca9ac1fc837','bbee0c65e6e3fab33f7693fb7d20be568f4ced27959faef43b149c6361f813fe','43c0c4401c99851d8f2c7d78543b104aef1e4ef9ac0033c2be85112afe45bbf6','b2ed801a870aeabdd7965d48033e105f5726f101713eb5a061bfa36a251ce29c')
CAPS=('CHOWN','DAC_OVERRIDE','FOWNER','SETUID','SETGID','SYS_CHROOT','KILL')
LABEL='org.openlxssh.audit-pair'
CLIENT_SHA='3a3653193ea51ee4880effcbbc0c6b295a77151e2fb60ec1c39b81081f96c385'
TOTAL_SECONDS=360
CASE_SECONDS=120
TMPFS={'/run':'rw,nosuid,nodev,noexec,size=96m,mode=0755','/tmp':'rw,nosuid,nodev,noexec,size=32m,mode=1777'}
HEALTH='python3 /opt/openlxssh-fixture/server.py health --authorized-run'
# Fixed metadata only: never read/export private keys, passwords or challenge files.
PUBLIC_META=r'''
import hashlib,json,os
from pathlib import Path
pid=int(Path('/run/openlxssh-fixture/sshd.pid').read_text());p=Path('/proc')/str(pid)
fields=(p/'stat').read_text().rsplit(')',1)[1].split()
status={line.split(':',1)[0]:line.split(':',1)[1].strip() for line in (p/'status').read_text().splitlines() if line.split(':',1)[0] in ('Uid','CapEff','CapPrm','CapBnd','NoNewPrivs')}
known=Path('/run/openlxssh-fixture/host_known_hosts').read_bytes();blob=__import__('base64').b64decode(known.split()[2])
fs=os.statvfs('/dev/shm')
print(json.dumps({'sshdPID':pid,'sshdStart':int(fields[19]),'sshdStatus':status,'hostKnownHostsSHA256':hashlib.sha256(known).hexdigest(),'hostFingerprint':'SHA256:'+__import__('base64').b64encode(hashlib.sha256(blob).digest()).decode().rstrip('='),'configSHA256':hashlib.sha256(Path('/run/openlxssh-fixture/sshd_config').read_bytes()).hexdigest(),'noDefaultRoute':not any(line.split()[1]=='00000000' for line in Path('/proc/net/route').read_text().splitlines()[1:]),'shmTotal':fs.f_blocks*fs.f_frsize,'shmAvailable':fs.f_bavail*fs.f_frsize},sort_keys=True))
'''
CLIENT_LOADER="import sys,types;code=sys.argv[1];mode=sys.argv[2];token=sys.argv[3];m=types.ModuleType('client_helper');exec(compile(code,'<fixed-client>','exec'),m.__dict__);original=m.argv; m.argv=lambda value:[('-T' if part=='-tt' and mode=='T' else part) for part in original(value)];raise SystemExit(m.execute(token))"

def names(run,case=None):
    if not re.fullmatch(r'[0-9a-f]{32}',run) or case not in (None,'A','B'):raise ValueError('runCase')
    prefix='openlxssh-audit-'+run
    return prefix+'-net' if case is None else (prefix+'-'+case.lower(),prefix+'-'+case.lower()+'-data')

def labels(run,case):return {LABEL:'v1',LABEL+'.run':run,LABEL+'.case':case}
def require_labels(item,run,case,container=False):
    actual=(item.get('Config',{}).get('Labels') or {}) if container else (item.get('Labels') or {})
    if any(actual.get(key)!=value for key,value in labels(run,case).items()):raise ValueError('notExactOwnedResource')
def caps(case):return list(CAPS)+(['AUDIT_WRITE'] if case=='B' else [])
def expected_mask(case):return 0x400eb | ((1<<29) if case=='B' else 0)
def create_args(run,case,network):
    container,volume=names(run,case)
    args=['create','--pull','never','--platform','linux/arm64','--name',container,'--network',network,'--read-only','--init','--restart','no','--security-opt','no-new-privileges:true','--cap-drop','ALL','--cpus','0.5','--memory','384m','--memory-swap','384m','--pids-limit','128','--ulimit','nofile=1024:1024','--shm-size','64m','--log-driver','none','--stop-timeout','5','--mount','type=volume,source='+volume+',target=/fixture']
    for key,value in labels(run,case).items():args+=['--label',key+'='+value]
    for cap in caps(case):args+=['--cap-add',cap]
    for path,options in TMPFS.items():args+=['--tmpfs',path+':'+options]
    return args+[IMAGE,'serve','--authorized-run','--mode','keyonly']

def verify_container(item,run,case,network_id):
    require_labels(item,run,case,True);host=item['HostConfig'];nets=item['NetworkSettings']['Networks'];mounts=item['Mounts'];name,volume=names(run,case)
    normalized={value.removeprefix('CAP_') for value in host['CapAdd']}
    attached=len(nets)==1 and next(iter(nets.values())).get('NetworkID')==network_id
    if item['State'].get('Status') in ('created','exited'):
        attached=not nets or (len(nets)==1 and next(iter(nets.values())).get('NetworkID') in ('',network_id))
    if (not re.fullmatch(r'[0-9a-f]{64}',item['Id']) or item['Name']!='/'+name or item['Image']!=IMAGE or normalized!=set(caps(case)) or host['CapDrop']!=['ALL']
        or host['Privileged'] is not False or host['ReadonlyRootfs'] is not True or host['SecurityOpt']!=['no-new-privileges:true'] or host['Init'] is not True
        or host['Memory']!=402653184 or host['MemorySwap']!=402653184 or host['NanoCpus']!=500000000 or host['PidsLimit']!=128 or host['ShmSize']!=67108864
        or host['LogConfig']['Type']!='none' or host.get('PortBindings') not in ({},None) or host['PublishAllPorts'] or host['RestartPolicy']['Name']!='no'
        or host['Tmpfs']!=TMPFS or host['NetworkMode']!=names(run) or not attached
        or len(mounts)!=1 or mounts[0]['Type']!='volume' or mounts[0]['Name']!=volume or mounts[0]['Destination']!='/fixture' or not mounts[0]['RW']
        or item['Config']['Entrypoint']!=['python3','/opt/openlxssh-fixture/server.py'] or item['Config']['Cmd']!=['serve','--authorized-run','--mode','keyonly']):raise ValueError('containerBoundary')
    if not any(limit.get('Name')=='nofile' and limit.get('Soft')==limit.get('Hard')==1024 for limit in host['Ulimits']):raise ValueError('nofile')

def verify_status(value,case):
    status=value['sshdStatus'];mask=expected_mask(case)
    if (status['Uid'].split()!=['0']*4 or any(int(status[key],16)!=mask for key in ('CapEff','CapPrm','CapBnd')) or status['NoNewPrivs']!='1'
        or not value['noDefaultRoute'] or value['shmTotal']!=67108864):raise ValueError('monitorCapabilityOrNamespace')

def expected_result(value,case,mode):
    if value.get('boundedFailure') is not None or value.get('rawLogged') is not False or not value.get('childReaped') or not value.get('pipesClosed'):return False
    if mode=='T':return value['exit']==0 and value['ackLF'] and not value['ackCRLF']
    return value['exit']==0 and value['ackCRLF'] if case=='B' else value['exit']==255 and not value['ackLF'] and not value['ackCRLF']

def live():
    # Imports only on explicit live action. Existing bounded metadata CLI owns/reaps
    # its direct Docker children; container helper has its independent25s alarm.
    spec=importlib.util.spec_from_file_location('audit_pair_relay',FIXTURE/'relay.py');relay=importlib.util.module_from_spec(spec);sys.modules[spec.name]=relay;sys.path.insert(0,str(FIXTURE));spec.loader.exec_module(relay)
    os.umask(0o077);run=uuid.uuid4().hex;root=HERE/'.build';root.mkdir(mode=0o700,exist_ok=True)
    if root.resolve()!=root or root.stat().st_uid!=os.getuid() or stat.S_IMODE(root.stat().st_mode)!=0o700:raise ValueError('evidenceRoot')
    evidence=root/('audit-pair-'+run);evidence.mkdir(mode=0o700);records=[];end=time.monotonic()+TOTAL_SECONDS
    environment={key:value for key,value in os.environ.items() if not key.startswith(('DOCKER_','BUILDX_','BUILDKIT_','COMPOSE_'))};environment['PATH']='/Applications/Docker.app/Contents/Resources/bin:/usr/bin:/bin:/usr/sbin:/sbin'
    def cli(args,deadline=end,seconds=12,limit=1048576):
        started=time.monotonic();command=[DOCKER,'--host',ENDPOINT]+args;entry={'argv':command,'expectedExit':0}
        try:
            output=relay._bounded_stdout(command,environment,min(deadline,time.monotonic()+seconds),threading.Event(),limit=limit);entry['exit']=0;return output
        except BaseException:entry['exit']='unknown_or_failure';raise
        finally:entry['seconds']=time.monotonic()-started;records.append(entry)
    def ledger(name,value):
        fd=os.open(evidence/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'w') as stream:json.dump(value,stream,sort_keys=True);stream.write('\n');stream.flush();os.fsync(stream.fileno())
    def query(args,**kw):return json.loads(cli(args,**kw))
    def original():
        items=query(['inspect']+list(ROOT_IDS),seconds=20);snapshot={}
        for identifier,item in zip(ROOT_IDS,items):
            labs=item['Config']['Labels']
            if item['Id']!=identifier or item['Image']!=IMAGE or item['State']['Health']['Status']!='healthy' or labs.get('org.openlxssh.fixture')!='env-fixture-a' or labs.get('com.docker.compose.project')!='openlxssh-fixture-61ed25328c13':raise ValueError('originalIdentity')
            snapshot[identifier]={key:item[key] for key in ('Id','Image','Name','Mounts','HostConfig')}
        snapshot['keyonlyPublic']=query(['exec','--user','0:0',ROOT_IDS[0],'/usr/bin/python3','-c',PUBLIC_META],limit=8192)
        return snapshot
    network_name=names(run);network_id=None;network_attempted=False;baseline=None;hashes={};results=[];failure=None;cleanup_ok=True;stage='prepared'
    ledger('prepared.json',{'run':run,'networkName':network_name,'caseNames':{case:names(run,case) for case in ('A','B')},'originalContainerIDs':ROOT_IDS,'image':IMAGE,'sourceSHA256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'totalSeconds':TOTAL_SECONDS,'caseSeconds':CASE_SECONDS,'fourCIDInspectSeconds':20,'metadataDefaultSeconds':12})
    def existing_container(name,deadline):
        ids=cli(['ps','-a','--no-trunc','-q','--filter','name=^/'+name+'$'],deadline).decode().split()
        if not ids:return None
        if len(ids)!=1:raise ValueError('ambiguousOwnContainer')
        return query(['inspect',ids[0]],deadline=deadline)[0]
    def remove_case(case,deadline):
        name,volume=names(run,case);item=existing_container(name,deadline)
        if item is not None:
            verify_container(item,run,case,network_id);identifier=item['Id']
            if item['State']['Running']:cli(['stop','--time','5',identifier],deadline,seconds=10)
            stopped=query(['inspect',identifier],deadline=deadline)[0];verify_container(stopped,run,case,network_id)
            if stopped['State']['Running']:raise ValueError('containerStillRunning')
            cli(['rm',identifier],deadline)
            if existing_container(name,deadline) is not None:raise ValueError('containerRemains')
        volumes=cli(['volume','ls','-q','--filter','name=^'+volume+'$'],deadline).decode().split()
        if volumes:
            if volumes!=[volume]:raise ValueError('volumeCollision')
            item=query(['volume','inspect',volume],deadline=deadline)[0];require_labels(item,run,case)
            if item['Name']!=volume:raise ValueError('volumeIdentity')
            cli(['volume','rm',volume],deadline)
    try:
        stage='preflight-client-source';client=(HERE/'client_helper.py').read_text()
        if hashlib.sha256(client.encode()).hexdigest()!=CLIENT_SHA:raise ValueError('reviewedClientChanged')
        stage='preflight-public-sources';public_paths=[FIXTURE/name for name in ('compose.yaml','Dockerfile','server.py','pam_fixture.py','pam-sshd','sshd_config.in')]
        hashes={str(path):hashlib.sha256(path.read_bytes()).hexdigest() for path in public_paths}
        stage='preflight-original';baseline=original()
        ledger('run-owned.json',{'run':run,'networkName':network_name,'caseNames':{case:names(run,case) for case in ('A','B')},'originalContainerIDs':ROOT_IDS,'image':IMAGE})
        stage='image';image=query(['image','inspect',IMAGE])[0]
        if image['Id']!=IMAGE or image['Architecture']!='arm64' or image['Os']!='linux' or image['Config']['Labels'].get('org.openlxssh.fixture.base')!=BASE:raise ValueError('imageProvenance')
        # Random names are NEVER adopted. Discovery is exact-name only.
        if cli(['network','ls','-q','--filter','name=^'+network_name+'$']).strip():raise ValueError('networkCollision')
        args=['network','create','--internal','--driver','bridge']
        for key,value in labels(run,'network').items():args+=['--label',key+'='+value]
        stage='network-create';network_attempted=True;network_id=cli(args+[network_name]).decode().strip()
        ledger('network-created.json',{'run':run,'networkID':network_id,'name':network_name,'labels':labels(run,'network')})
        if not re.fullmatch(r'[0-9a-f]{64}',network_id):raise ValueError('fullNetworkID')
        network=query(['network','inspect',network_id])[0];require_labels(network,run,'network')
        if network['Id']!=network_id or network['Name']!=network_name or not network['Internal'] or network['Driver']!='bridge' or network.get('Containers'):raise ValueError('networkBoundary')
        for case in ('A','B'):
            deadline=min(end-30,time.monotonic()+CASE_SECONDS);name,volume=names(run,case);case_result={'case':case,'capAdd':caps(case),'monitorMaskExpected':hex(expected_mask(case))}
            try:
                if existing_container(name,deadline) is not None or cli(['volume','ls','-q','--filter','name=^'+volume+'$'],deadline).strip():raise ValueError('caseCollision')
                args=['volume','create']
                for key,value in labels(run,case).items():args+=['--label',key+'='+value]
                stage=case+'-volume-create'
                if cli(args+[volume],deadline).decode().strip()!=volume:raise ValueError('volumeCreate')
                ledger(case+'-volume-created.json',{'run':run,'case':case,'volume':volume,'labels':labels(run,case)})
                vol=query(['volume','inspect',volume],deadline=deadline)[0];require_labels(vol,run,case)
                stage=case+'-container-create';cid=cli(create_args(run,case,network_name),deadline).decode().strip()
                ledger(case+'-container-created.json',{'run':run,'case':case,'containerID':cid,'volume':volume,'networkID':network_id,'labels':labels(run,case)})
                if not re.fullmatch(r'[0-9a-f]{64}',cid):raise ValueError('fullContainerID')
                item=query(['inspect',cid],deadline=deadline)[0];verify_container(item,run,case,network_id);case_result['container']=cid
                stage=case+'-bootstrap';cli(['start',cid],deadline)
                ready_limit=min(deadline-60,time.monotonic()+60)
                while time.monotonic()<ready_limit:
                    item=query(['inspect',cid],deadline=deadline)[0];verify_container(item,run,case,network_id)
                    if not item['State']['Running']:raise ValueError('bootstrapExited')
                    try:
                        cli(['exec','--user','0:0',cid,'python3','/opt/openlxssh-fixture/server.py','health','--authorized-run'],deadline,seconds=5,limit=0);break
                    except Exception:time.sleep(.5)
                else:raise TimeoutError('bootstrapDeadline')
                stage=case+'-monitor-metadata'
                meta=query(['exec','--user','0:0',cid,'/usr/bin/python3','-c',PUBLIC_META],deadline=deadline,limit=8192);verify_status(meta,case);case_result['publicMetadata']=meta;case_result['clients']=[]
                for mode in ('T','TT'):
                    stage=case+'-client-'+mode;token=uuid.uuid4().hex
                    value=query(['exec','--user','0:0',cid,'/usr/bin/python3','-c',CLIENT_LOADER,client,mode,token],deadline=deadline,seconds=35,limit=4096)
                    case_result['clients'].append({'mode':mode,'result':value})
                    if value.get('token')!=token or not expected_result(value,case,mode):raise ValueError('unexpectedClientOutcome')
                case_result['status']='expected-outcomes'
            finally:
                results.append(case_result)
                try:remove_case(case,min(end,time.monotonic()+25));case_result['cleanup']='exact-stopped-container-and-volume-removed'
                except Exception:cleanup_ok=False;case_result['cleanup']='failed-retain-identities';raise
    except BaseException as error:failure=type(error).__name__
    finally:
        if network_attempted and network_id is None:
            try:
                ids=cli(['network','ls','--no-trunc','-q','--filter','name=^'+network_name+'$'],deadline=time.monotonic()+10).decode().split()
                if len(ids)>1:raise ValueError('networkCollision')
                if ids:
                    candidate=query(['network','inspect',ids[0]],deadline=time.monotonic()+10)[0];require_labels(candidate,run,'network')
                    if candidate['Name']!=network_name or candidate['Id']!=ids[0]:raise ValueError('networkIdentity')
                    network_id=candidate['Id']
            except Exception:cleanup_ok=False
        if network_id is not None:
            try:
                network=query(['network','inspect',network_id],deadline=time.monotonic()+10)[0];require_labels(network,run,'network')
                if network['Id']!=network_id or network.get('Containers'):raise ValueError('networkNotEmpty')
                cli(['network','rm',network_id],deadline=time.monotonic()+10)
            except Exception:cleanup_ok=False
        original_unchanged=None
        if baseline is not None:
            try:
                if original()!=baseline or any(hashlib.sha256(Path(path).read_bytes()).hexdigest()!=sha for path,sha in hashes.items()):raise ValueError('originalChanged')
                original_unchanged=True
            except Exception:original_unchanged=False;failure=failure or 'original-postcheck-failed'
        report={'task':'FIXTURE-AUDIT-PAIR-PREP-A','run':run,'image':IMAGE,'results':results,'failure':failure,'failedStage':stage if failure else None,'healthSupervision':'Both companions omit daemon Healthcheck; same fixed server.py health argv polled <=60s (difference from original Compose CMD health only)','cleanupComplete':cleanup_ok,'originalUnchanged':original_unchanged,'originalBefore':baseline,'publicSourceHashes':hashes,'networkID':network_id,'noHostPortOrBind':True,'onlyCapabilityDifference':'AUDIT_WRITE bit29 (VM kernel write, not private log/control/read)'}
        (evidence/'result.json').write_text(json.dumps(report,indent=2)+'\n');(evidence/'commands.json').write_text(json.dumps(records,indent=2)+'\n')
    print('Audit pair metadata only: '+str(evidence/'result.json'))
    return 0 if failure is None and cleanup_ok and original_unchanged and len(results)==2 else 2

def main(args=None):
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('action',choices=('help','plan','live'),nargs='?',default='help');parser.add_argument('--authorized-isolated-pair',action='store_true');parser.add_argument('--primary-reviewed',action='store_true');options=parser.parse_args(args)
    if options.action=='help':parser.print_help();return 0
    if options.action=='plan':print('Fixed A/B serial keyonly, exact image, own internal network/empty volumes, no host ports; only B adds AUDIT_WRITE. No I/O.');return 0
    if not options.authorized_isolated_pair or not options.primary_reviewed:parser.error('explicit isolated pair authorization AND primary review required')
    return live()

if __name__=='__main__':
    try:sys.exit(main())
    except Exception:os.write(2,b'Fixed audit pair refused; no raw/private output.\n');sys.exit(2)
