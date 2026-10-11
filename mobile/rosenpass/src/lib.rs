//! Packet-only FFI around the pinned Rosenpass protocol. This library opens
//! no sockets, files, subprocesses, VPN interfaces or background threads.
use std::collections::HashMap;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::{Arc, LazyLock, Mutex, Once};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::{ptr, slice};
use rosenpass::protocol::basic_types::{MsgBuf, SPk, SSk};
use rosenpass::protocol::osk_domain_separator::OskDomainSeparator;
use rosenpass::protocol::{CryptoServer, PeerPtr, PollResult, ProtocolVersion};
use rosenpass_cipher_traits::primitives::Kem;
use rosenpass_ciphers::StaticKem;
use zeroize::Zeroizing;

const LIMIT: usize = 8;
const CHANGED: u32 = 1;
const EXPIRED: u32 = 2;
const FAULT: i32 = -1;
const REJECTED: i32 = -2;
static MEMORY: Once = Once::new();
static NEXT: AtomicU64 = AtomicU64::new(1);
static SESSIONS: LazyLock<Mutex<HashMap<u64, Arc<Owner>>>> = LazyLock::new(|| Mutex::new(HashMap::new()));
struct Owner { closed: AtomicBool, session: Mutex<Option<Session>> }
struct Session { core: CryptoServer, peer: PeerPtr }
struct Event { packet: Vec<u8>, key: Option<Zeroizing<[u8;32]>>, flags: u32, wait_ms: u64 }
impl Event { fn new()->Self {Self{packet:Vec::new(),key:None,flags:0,wait_ms:1000}} }
fn guard(f:impl FnOnce()->Result<(),i32>)->i32 {
    match catch_unwind(AssertUnwindSafe(f)){Ok(Ok(()))=>0,Ok(Err(code))=>code,Err(_)=>FAULT}
}
fn memory_policy(){MEMORY.call_once(rosenpass_secret_memory::secret_policy_try_use_memfd_secrets);}
fn owner(id:u64)->Result<Arc<Owner>,i32>{SESSIONS.lock().map_err(|_|FAULT)?.get(&id).cloned().ok_or(FAULT)}
fn create(sk:&[u8],pk:&[u8],peer:&[u8],version:u32)->Result<u64,i32>{
    if sk.len()!=StaticKem::SK_LEN||pk.len()!=StaticKem::PK_LEN||peer.len()!=StaticKem::PK_LEN
        ||pk==peer||![2,3].contains(&version)||sk.iter().all(|b|*b==0)||pk.iter().all(|b|*b==0)||peer.iter().all(|b|*b==0){return Err(FAULT);}
    memory_policy();
    let mut all=SESSIONS.lock().map_err(|_|FAULT)?;
    if all.len()>=LIMIT{return Err(FAULT);}
    let id=NEXT.fetch_update(Ordering::Relaxed,Ordering::Relaxed,|n|n.checked_add(1)).map_err(|_|FAULT)?;
    let mut secret=SSk::zero();secret.secret_mut().copy_from_slice(sk);
    let mut public=SPk::zero();public.copy_from_slice(pk);
    let mut remote=SPk::zero();remote.copy_from_slice(peer);
    let mut core=CryptoServer::new(secret,public);
    let peer=core.add_peer(None,remote,if version==2{ProtocolVersion::V02}else{ProtocolVersion::V03},OskDomainSeparator::for_wireguard_psk()).map_err(|_|FAULT)?;
    all.insert(id,Arc::new(Owner{closed:AtomicBool::new(false),session:Mutex::new(Some(Session{core,peer}))}));Ok(id)
}
impl Session {
    fn step(&mut self,kind:u32,input:&[u8])->Result<Event,i32>{
        let mut event=Event::new();let mut tx=MsgBuf::zero();
        match kind {
            0=>{
                if !input.is_empty(){return Err(FAULT);}
                match self.core.poll().map_err(|_|FAULT)? {
                    PollResult::Sleep(seconds)=>{
                        if seconds.is_nan()||seconds<0.0{return Err(FAULT);}
                        event.wait_ms=(seconds.min(1.0)*1000.0).ceil() as u64;
                    },
                    PollResult::DeleteKey(p)=>{if p.0!=self.peer.0{return Err(FAULT);}event.flags=EXPIRED;event.wait_ms=0;},
                    PollResult::SendInitiation(p)=>{
                        if p.0!=self.peer.0{return Err(FAULT);}
                        let n=self.core.initiate_handshake(p,&mut tx[..]).map_err(|_|FAULT)?;
                        event.packet.extend_from_slice(tx.get(..n).ok_or(FAULT)?);event.wait_ms=0;
                    },
                    PollResult::SendRetransmission(p)=>{
                        if p.0!=self.peer.0{return Err(FAULT);}
                        let n=self.core.retransmit_handshake(p,&mut tx[..]).map_err(|_|FAULT)?;
                        event.packet.extend_from_slice(tx.get(..n).ok_or(FAULT)?);event.wait_ms=0;
                    }
                }
            },
            1=>{
                if input.is_empty()||input.len()>tx.len(){return Err(REJECTED);}
                let result=self.core.handle_msg(input,&mut tx[..]).map_err(|_|REJECTED)?;
                if let Some(p)=result.exchanged_with {
                    if p.0!=self.peer.0{return Err(FAULT);}
                    let key=self.core.osk(p).map_err(|_|FAULT)?;
                    let mut value=Zeroizing::new([0u8;32]);value.copy_from_slice(key.secret());
                    event.key=Some(value);event.flags=CHANGED;
                }
                if let Some(n)=result.resp{event.packet.extend_from_slice(tx.get(..n).ok_or(FAULT)?);}
            },
            2=>{
                if !input.is_empty(){return Err(FAULT);}
                let n=self.core.initiate_handshake(self.peer,&mut tx[..]).map_err(|_|FAULT)?;
                event.packet.extend_from_slice(tx.get(..n).ok_or(FAULT)?);
            },
            _=>return Err(FAULT)
        }
        Ok(event)
    }
}
#[no_mangle]
pub extern "C" fn routervpn_rp_abi_version()->u32{1}
#[no_mangle]
pub extern "C" fn routervpn_rp_secret_size()->usize{StaticKem::SK_LEN}
#[no_mangle]
pub extern "C" fn routervpn_rp_public_size()->usize{StaticKem::PK_LEN}
#[no_mangle]
pub extern "C" fn routervpn_rp_packet_size()->usize{rosenpass::msgs::MAX_MESSAGE_LEN}

/// # Safety
/// All pointers must reference nonoverlapping buffers of the indicated sizes
/// for this call. `out` points to writable u64 storage. No pointer is retained.
#[no_mangle]
pub unsafe extern "C" fn routervpn_rp_new(sk:*const u8,sk_len:usize,pk:*const u8,pk_len:usize,
    peer:*const u8,peer_len:usize,version:u32,out:*mut u64)->i32{
    if out.is_null(){return FAULT;}*out=0;
    if sk.is_null()||pk.is_null()||peer.is_null()||sk_len!=StaticKem::SK_LEN||pk_len!=StaticKem::PK_LEN||peer_len!=StaticKem::PK_LEN{return FAULT;}
    guard(||{*out=create(slice::from_raw_parts(sk,sk_len),slice::from_raw_parts(pk,pk_len),slice::from_raw_parts(peer,peer_len),version)?;Ok(())})
}
/// # Safety
/// Buffers must be valid, nonoverlapping and caller-owned for the entire call.
/// Kind 0 polls, 1 receives a peer datagram, 2 initiates a handshake. Key and
/// length/status outputs are cleared before lookup, including on failure.
#[no_mangle]
pub unsafe extern "C" fn routervpn_rp_step(id:u64,kind:u32,input:*const u8,input_len:usize,
    tx:*mut u8,tx_cap:usize,tx_len:*mut usize,key:*mut u8,key_cap:usize,flags:*mut u32,wait_ms:*mut u64)->i32{
    if tx_len.is_null()||flags.is_null()||wait_ms.is_null()||key.is_null()||key_cap!=32{return FAULT;}
    *tx_len=0;*flags=0;*wait_ms=1000;ptr::write_bytes(key,0,32);
    if tx.is_null()||tx_cap<rosenpass::msgs::MAX_MESSAGE_LEN||input_len>rosenpass::msgs::MAX_MESSAGE_LEN||(input_len>0&&input.is_null()){return FAULT;}
    guard(||{
        let current=owner(id)?;let mut locked=current.session.lock().map_err(|_|FAULT)?;
        if current.closed.load(Ordering::Acquire){return Err(FAULT);}
        let session=locked.as_mut().ok_or(FAULT)?;
        let input=if input_len==0{&[]}else{slice::from_raw_parts(input,input_len)};
        let event=session.step(kind,input)?;
        if current.closed.load(Ordering::Acquire){return Err(FAULT);}
        if event.packet.len()>tx_cap{return Err(FAULT);}
        ptr::copy_nonoverlapping(event.packet.as_ptr(),tx,event.packet.len());*tx_len=event.packet.len();
        if let Some(material)=event.key{ptr::copy_nonoverlapping(material.as_ptr(),key,32);}
        *flags=event.flags;*wait_ms=event.wait_ms;
        // Hold session lock through output publication: Close cannot return
        // while any call can still publish a key from this handle.
        Ok(())
    })
}
#[no_mangle]
pub extern "C" fn routervpn_rp_close(id:u64)->i32{
    guard(||{
        let current=SESSIONS.lock().map_err(|_|FAULT)?.get(&id).cloned();
        if let Some(current)=current{
            current.closed.store(true,Ordering::Release);
            {let mut locked=current.session.lock().unwrap_or_else(|p|p.into_inner());locked.take();}
            // Keep the registry entry until teardown finishes. Concurrent
            // Close calls all wait on the same session rather than returning early.
            let mut all=SESSIONS.lock().map_err(|_|FAULT)?;
            if all.get(&id).map(|p|Arc::ptr_eq(p,&current)).unwrap_or(false){all.remove(&id);}
        }
        Ok(())
    })
}

#[cfg(test)]
mod tests{
    use super::*;
    use std::ops::DerefMut;
    fn keys()->(SSk,SPk){memory_policy();let(mut s,mut p)=(SSk::zero(),SPk::zero());StaticKem.keygen(s.secret_mut(),p.deref_mut()).unwrap();(s,p)}
    fn open(s:&SSk,p:&SPk,remote:&SPk,version:u32)->u64{
        let mut id=0;
        assert_eq!(unsafe{routervpn_rp_new(s.secret().as_ptr(),s.secret().len(),p.as_ptr(),p.len(),remote.as_ptr(),remote.len(),version,&mut id)},0);assert_ne!(id,0);id
    }
    fn call(id:u64,kind:u32,input:&[u8])->(i32,Vec<u8>,Zeroizing<[u8;32]>,u32){
        let mut tx=vec![0u8;routervpn_rp_packet_size()];let mut n=99;let mut key=Zeroizing::new([0x55u8;32]);let mut flags=99;let mut wait=9999;
        let rc=unsafe{routervpn_rp_step(id,kind,input.as_ptr(),input.len(),tx.as_mut_ptr(),tx.len(),&mut n,key.as_mut_ptr(),32,&mut flags,&mut wait)};
        assert!(wait<=1000);assert!(n<=tx.len());tx.truncate(n);(rc,tx,key,flags)
    }
    #[test]
    fn real_upstream_exchange_and_rekey_both_versions(){
        let(sa,pa)=keys();let(sb,pb)=keys();
        for version in [2,3]{
            let(a,b)=(open(&sa,&pa,&pb,version),open(&sb,&pb,&pa,version));let mut previous:Option<Zeroizing<[u8;32]>>=None;
            for _ in 0..3{
                let(rc,mut packet,_,_)=call(a,2,&[]);assert_eq!(rc,0);assert!(!packet.is_empty());
                let(mut left,mut right)=(None,None);let mut target=b;
                for _ in 0..12{
                    if packet.is_empty(){break;}
                    let(rc,next,key,flags)=call(target,1,&packet);assert_eq!(rc,0);
                    if flags&CHANGED!=0{assert!(key.iter().any(|b|*b!=0));if target==a{left=Some(key)}else{right=Some(key)}}
                    packet=next;target=if target==a{b}else{a};
                }
                let left=left.expect("initiator authenticated key missing");let right=right.expect("responder authenticated key missing");
                assert_eq!(&*left,&*right);if let Some(old)=previous{assert_ne!(&*left,&*old);}previous=Some(left);
            }
            let(rc,_,key,flags)=call(a,1,b"not a Rosenpass packet");assert_eq!(rc,REJECTED);assert_eq!(flags,0);assert_eq!(&*key,&[0u8;32]);
            assert_eq!(routervpn_rp_close(a),0);assert_eq!(routervpn_rp_close(b),0);
            let(rc,packet,key,flags)=call(a,0,&[]);assert_eq!(rc,FAULT);assert!(packet.is_empty());assert_eq!(flags,0);assert_eq!(&*key,&[0u8;32]);
        }
    }
    #[test]
    fn invalid_inputs_clear_outputs(){
        let mut id=123;
        assert_eq!(unsafe{routervpn_rp_new(ptr::null(),0,ptr::null(),0,ptr::null(),0,2,&mut id)},FAULT);assert_eq!(id,0);
        let(rc,packet,key,flags)=call(u64::MAX,0,&[]);assert_eq!(rc,FAULT);assert!(packet.is_empty());assert_eq!(flags,0);assert_eq!(&*key,&[0u8;32]);
    }
    #[test]
    fn concurrent_close_joins_and_revokes_handle(){
        let(sa,pa)=keys();let(_,pb)=keys();let id=open(&sa,&pa,&pb,2);
        let mut threads=Vec::new();
        for _ in 0..8{threads.push(std::thread::spawn(move||{assert_eq!(routervpn_rp_close(id),0);let(rc,_,key,flags)=call(id,0,&[]);assert_eq!(rc,FAULT);assert_eq!(flags,0);assert_eq!(&*key,&[0u8;32]);}));}
        for thread in threads{thread.join().unwrap();}
    }
}
