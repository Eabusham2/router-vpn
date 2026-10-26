// Package mobilepq owns the native Rosenpass handshake and key lifetime.
// It opens no OS interface and never chooses a fallback transport or resolver.
package mobilepq

import (
 "context"
 "errors"
 "io"
 "net"
 "sync"
 "sync/atomic"
 "time"
)

var (
 ErrPending=errors.New("post-quantum exchange is not ready")
 ErrExpired=errors.New("post-quantum key expired")
 ErrPacket=errors.New("rejected Rosenpass datagram")
 ErrStopped=errors.New("post-quantum session stopped")
 ErrCleanup=errors.New("post-quantum cleanup could not be confirmed")
)
// Protocol implements only the exact pinned cryptographic state machine.
// Kind 0 polls; kind 1 handles one peer datagram. Close must join native work.
type Protocol interface {Step(kind uint32,packet []byte)(Event,error);Close()error}
type Event struct {Packet []byte;Key []byte;Expired bool;Wait time.Duration}
// Target is one captured WG/AWG peer, not a process-global active interface.
// Apply installs the PSK before initial tunnel startup and for later rekeys.
// Revoke must fail closed, never replace the required PSK with an all-zero key.
type Target interface {ApplyPQKey([]byte)error;RevokePQKey()error}
// Dial must honor cancellation and return a connected datagram transport to
// the captured Rosenpass peer, protected by the app's native underlay owner.
// Initial exchange cannot depend on the WG/AWG tunnel whose PSK it establishes.
type Dial func(context.Context)(net.Conn,error)

type Controller struct{
 mu sync.Mutex
 ctx context.Context
 cancel context.CancelFunc
 protocol Protocol
 target Target
 dial Dial
 conn net.Conn
 started,closing bool
 ready atomic.Bool
 done,initial chan struct{}
 notify,cleanup sync.Once
 failure,closeErr error
 timeout time.Duration
}
func New(ctx context.Context,protocol Protocol,target Target,dial Dial)(*Controller,error){
 if ctx==nil||protocol==nil||target==nil||dial==nil{return nil,errors.New("PQ requires captured protocol, peer and transport owners")}
 child,cancel:=context.WithCancel(ctx)
 return &Controller{ctx:child,cancel:cancel,protocol:protocol,target:target,dial:dial,done:make(chan struct{}),initial:make(chan struct{}),timeout:30*time.Second},nil
}
func(c *Controller)Start()error{
 c.mu.Lock()
 if c.started||c.closing||c.ctx.Err()!=nil{c.mu.Unlock();return ErrStopped}
 c.started=true;go c.run();c.mu.Unlock()
 timer:=time.NewTimer(c.timeout);defer timer.Stop()
 select{
 case <-c.initial:
  if c.Ready(){return nil};_ = c.Close();return c.Err()
 case <-timer.C:
  cleanup:=c.Close();return errors.Join(errors.New("post-quantum exchange timed out"),cleanup)
 case <-c.ctx.Done():
  cleanup:=c.Close();return errors.Join(c.Err(),cleanup)
 }
}
func(c *Controller)Ready()bool{return c!=nil&&c.ready.Load()&&c.ctx.Err()==nil}
func(c *Controller)Err()error{
 c.mu.Lock();defer c.mu.Unlock()
 if c.failure!=nil{return c.failure};if c.closing||c.ctx.Err()!=nil{return ErrStopped};return ErrPending
}
func erase(value []byte){for i:=range value{value[i]=0}}
func(c *Controller)deliver(event Event)error{
 defer erase(event.Key)
 if c.ctx.Err()!=nil{return ErrStopped}
 if event.Expired{return ErrExpired}
 if len(event.Packet)>65535||(len(event.Key)!=0&&len(event.Key)!=32){return errors.New("invalid pinned PQ event")}
 // An authenticated reply may let the remote peer adopt this key immediately.
 // Install locally first; never acknowledge a rejected or cancelled adoption.
 // Initial readiness is published only after both installation and delivery.
 if len(event.Key)>0{
  var nonzero byte;for _,b:=range event.Key{nonzero|=b};if nonzero==0{return errors.New("invalid authenticated PQ key")}
  c.mu.Lock()
  if c.closing||c.ctx.Err()!=nil{c.mu.Unlock();return ErrStopped}
  err:=c.target.ApplyPQKey(event.Key)
  c.mu.Unlock()
  if err!=nil{return errors.New("captured native peer refused the PQ key")}
  if c.ctx.Err()!=nil{return ErrStopped}
 }
 if len(event.Packet)>0{
  if err:=c.conn.SetWriteDeadline(time.Now().Add(time.Second));err!=nil{return errors.New("PQ transport lacks enforced write deadlines")}
  n,err:=c.conn.Write(event.Packet);if err!=nil{return errors.New("PQ transport write failed")};if n!=len(event.Packet){return io.ErrShortWrite}
 }
 if len(event.Key)>0{
  c.mu.Lock()
  if c.closing||c.ctx.Err()!=nil{c.mu.Unlock();return ErrStopped}
  c.ready.Store(true);c.notify.Do(func(){close(c.initial)})
  c.mu.Unlock()
 }
 if c.ctx.Err()!=nil{return ErrStopped}
 return nil
}
func(c *Controller)run(){
 failure:=ErrStopped
 defer func(){c.finish(failure)}()
 watcherDone:=make(chan struct{})
 stopWatcher:=context.AfterFunc(c.ctx,func(){defer close(watcherDone);c.mu.Lock();conn:=c.conn;c.mu.Unlock();if conn!=nil{_ = conn.Close()}})
 defer func(){if !stopWatcher(){<-watcherDone}}()
 // Native packet transports retain this context as their connection owner.
 // Bound admission independently, then keep the admitted owner until run exits.
 dialContext,cancelDial:=context.WithCancel(c.ctx);defer cancelDial()
 deadline:=time.Now().Add(5*time.Second)
 admission:=time.AfterFunc(5*time.Second,cancelDial)
 conn,err:=c.dial(dialContext)
 admitted:=admission.Stop()&&time.Now().Before(deadline)
 if !admitted||dialContext.Err()!=nil||err!=nil||conn==nil{
  if conn!=nil{_ = conn.Close()};failure=errors.New("protected PQ peer transport could not open");return
 }
 c.mu.Lock()
 if c.closing||c.ctx.Err()!=nil{c.mu.Unlock();_ = conn.Close();return}
 c.conn=conn;c.mu.Unlock()
 buffer:=make([]byte,65535);defer erase(buffer)
 for c.ctx.Err()==nil{
  event,err:=c.protocol.Step(0,nil)
  if err!=nil{erase(event.Key);failure=errors.New("pinned PQ timer failed");return}
  if err=c.deliver(event);err!=nil{failure=err;return}
  wait:=event.Wait;if wait<=0{wait=time.Millisecond};if wait>time.Second{wait=time.Second}
  if err=conn.SetReadDeadline(time.Now().Add(wait));err!=nil{failure=errors.New("PQ transport lacks enforced read deadlines");return}
  n,err:=conn.Read(buffer)
  if err!=nil{
   if c.ctx.Err()!=nil{return}
   if netErr,ok:=err.(net.Error);ok&&netErr.Timeout(){continue}
   failure=errors.New("protected PQ peer transport closed");return
  }
  if n<=0||n>len(buffer){continue}
  event,err=c.protocol.Step(1,buffer[:n])
  if err!=nil{erase(event.Key);if errors.Is(err,ErrPacket){continue};failure=errors.New("pinned PQ packet processing failed");return}
  if err=c.deliver(event);err!=nil{failure=err;return}
 }
}
func(c *Controller)finish(failure error){
 c.cleanup.Do(func(){
  c.ready.Store(false);c.cancel()
  c.mu.Lock();conn:=c.conn;c.mu.Unlock()
  if conn!=nil{_ =conn.Close()}
  var cleanup error
  if err:=c.target.RevokePQKey();err!=nil{cleanup=ErrCleanup}
  if err:=c.protocol.Close();err!=nil{cleanup=ErrCleanup}
  c.mu.Lock();c.failure=errors.Join(failure,cleanup);c.closeErr=cleanup;c.mu.Unlock()
  c.notify.Do(func(){close(c.initial)});close(c.done)
 })
}
func(c *Controller)Close()error{
 if c==nil{return nil}
 c.cancel();c.ready.Store(false)
 c.mu.Lock();c.closing=true;started:=c.started;conn:=c.conn;c.mu.Unlock()
 if conn!=nil{_ =conn.Close()}
 if !started{c.finish(ErrStopped)}
 <-c.done
 c.mu.Lock();defer c.mu.Unlock();return c.closeErr
}
