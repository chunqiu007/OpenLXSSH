import Darwin
import Foundation

/// Sole FD owner. Closing is idempotent and clears ownership BEFORE close;
/// polling never leaves ownership to an unbounded worker or discovers a process.
final class PeerDescriptors:@unchecked Sendable {
    private let lock=NSLock()
    private var listener:Int32 = -1,accepted:Int32 = -1
    func ownListener(_ fd:Int32)throws {lock.lock();defer{lock.unlock()};guard fd>=0,listener<0 else {throw TimeoutFailure.resource};listener=fd}
    func ownAccepted(_ fd:Int32)throws {lock.lock();defer{lock.unlock()};guard fd>=0,accepted<0 else {throw TimeoutFailure.resource};accepted=fd}
    func listenerFD()->Int32 {lock.lock();defer{lock.unlock()};return listener}
    func closeListener(){lock.lock();let fd=listener;listener = -1;lock.unlock();if fd>=0 {_=Darwin.close(fd)}}
    func closeAccepted(){lock.lock();let fd=accepted;accepted = -1;lock.unlock();if fd>=0 {_=Darwin.close(fd)}}
    func closeAll(){closeListener();closeAccepted()}
    func count()->Int {lock.lock();defer{lock.unlock()};return (listener>=0 ? 1:0)+(accepted>=0 ? 1:0)}
    deinit{closeAll()}
}

/// Fixed-address raw TCP peer only. It never calls read/recv/write/send on the
/// accepted socket. Kernel receive buffers are not read, logged or snapshotted.
final class SilentPeer:@unchecked Sendable {
    private let descriptors=PeerDescriptors()
    private let lock=NSLock()
    private var started=false,stopRequested=false,completed=false,expired=false,accepts=0
    private var task:Task<Void,Never>?
    private var start:UInt64=0
    func startOnce()throws {
        lock.lock();guard !started else {lock.unlock();throw TimeoutFailure.listener};started=true;start=DispatchTime.now().uptimeNanoseconds;lock.unlock()
        let fd=Darwin.socket(AF_INET,SOCK_STREAM,IPPROTO_TCP)
        guard fd>=0 else {throw TimeoutFailure.listener}
        do {
            try descriptors.ownListener(fd)
            guard fcntl(fd,F_SETFD,FD_CLOEXEC)==0,fcntl(fd,F_SETFL,O_NONBLOCK)==0 else {throw TimeoutFailure.listener}
            var address=sockaddr_in();address.sin_len=UInt8(MemoryLayout<sockaddr_in>.size);address.sin_family=sa_family_t(AF_INET)
            address.sin_port=TimeoutFixed.port.bigEndian
            guard inet_pton(AF_INET,TimeoutFixed.host,&address.sin_addr)==1 else {throw TimeoutFailure.listener}
            let result=withUnsafePointer(to:&address){$0.withMemoryRebound(to:sockaddr.self,capacity:1){Darwin.bind(fd,$0,socklen_t(MemoryLayout<sockaddr_in>.size))}}
            // No REUSEADDR, REUSEPORT, fallback address or alternate port.
            guard result==0,Darwin.listen(fd,1)==0 else {throw TimeoutFailure.listener}
            task=Task.detached{[self] in await loop()}
        }catch{descriptors.closeAll();throw error}
    }
    private func stopped()->Bool {lock.lock();defer{lock.unlock()};return stopRequested}
    private func markAccepted(){lock.lock();accepts+=1;lock.unlock()}
    private func requestStop()->Task<Void,Never>?{lock.lock();defer{lock.unlock()};stopRequested=true;return task}
    private func snapshot()->PeerSnapshot {
        lock.lock();defer{lock.unlock()}
        return PeerSnapshot(accepted:accepts,sentBytes:0,readCalls:0,openOwnedFDs:descriptors.count(),listenerClosed:true,acceptedClosed:true,taskCompleted:completed,expired:expired,elapsedSeconds:Double(DispatchTime.now().uptimeNanoseconds-start)/1e9)
    }
    private func finish(expired:Bool){descriptors.closeAll();lock.lock();self.expired=expired;completed=true;lock.unlock()}
    private func loop()async {
        let deadline=start+UInt64(TimeoutFixed.peerSeconds*1e9)
        while !stopped() && DispatchTime.now().uptimeNanoseconds<deadline {
            let fd=descriptors.listenerFD()
            if fd>=0 {
                var address=sockaddr_storage(),length=socklen_t(MemoryLayout<sockaddr_storage>.size)
                let accepted=withUnsafeMutablePointer(to:&address){$0.withMemoryRebound(to:sockaddr.self,capacity:1){Darwin.accept(fd,$0,&length)}}
                if accepted>=0 {
                    var adopted=false
                    do {
                        guard address.ss_family==sa_family_t(AF_INET) else {throw TimeoutFailure.listener}
                        try descriptors.ownAccepted(accepted);adopted=true
                        guard fcntl(accepted,F_SETFD,FD_CLOEXEC)==0,fcntl(accepted,F_SETFL,O_NONBLOCK)==0 else {throw TimeoutFailure.listener}
                        markAccepted()
                        descriptors.closeListener() // exactly one accept, no further admission
                    }catch{if !adopted{_=Darwin.close(accepted)};finish(expired:false);return}
                }else if errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR {finish(expired:false);return}
            }
            // Keep accepted FD silent and alive; never inspect received bytes.
            do{try await Task.sleep(for:.milliseconds(5))}catch{break}
        }
        finish(expired:!stopped() && DispatchTime.now().uptimeNanoseconds>=deadline)
    }
    func stopAndWait()async->PeerSnapshot {
        let pending=requestStop()
        // loop has no blocking I/O and checks stop every5ms. Await the actual
        // finite task, not a fire-and-forget close or descriptor-number kill.
        if let pending {await pending.value}
        descriptors.closeAll()
        return snapshot()
    }
}
