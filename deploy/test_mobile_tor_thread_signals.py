#!/usr/bin/env python3
"""Prove the shipping C host keeps SIGPIPE protection local to Tor threads."""
from pathlib import Path
import argparse
import os
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
HEADER = '''
#ifndef TOR_API_H
#define TOR_API_H
typedef struct tor_main_configuration_t tor_main_configuration_t;
tor_main_configuration_t *tor_main_configuration_new(void);
void tor_main_configuration_free(tor_main_configuration_t *);
int tor_main_configuration_set_command_line(tor_main_configuration_t *, int, char **);
int tor_run_main(const tor_main_configuration_t *);
const char *tor_api_get_provider_version(void);
#endif
'''
FIXTURE = r'''
#define _POSIX_C_SOURCE 200809L
#include "routervpn_tor_host.h"
#include "tor_api.h"
#include <pthread.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
struct tor_main_configuration_t { int unused; };
static volatile sig_atomic_t caught;
static void host_handler(int sig) { if (sig == SIGPIPE) caught++; }
tor_main_configuration_t *tor_main_configuration_new(void) { return calloc(1,sizeof(tor_main_configuration_t)); }
void tor_main_configuration_free(tor_main_configuration_t *p) { free(p); }
int tor_main_configuration_set_command_line(tor_main_configuration_t *p,int argc,char **argv) { (void)p;(void)argc;(void)argv;return 0; }
const char *tor_api_get_provider_version(void) { return "signal fixture"; }
static void *child(void *value) {
 int *failure=value;sigset_t mask;
 if(pthread_sigmask(SIG_SETMASK,NULL,&mask)!=0 || sigismember(&mask,SIGPIPE)!=1) {*failure=62;return NULL;}
 if(pthread_kill(pthread_self(),SIGPIPE)!=0) *failure=63;
 return NULL;
}
int tor_run_main(const tor_main_configuration_t *cfg) {
 (void)cfg;sigset_t mask;struct sigaction action;
 if(pthread_sigmask(SIG_SETMASK,NULL,&mask)!=0 || sigismember(&mask,SIGPIPE)!=1) return 61;
 if(sigaction(SIGPIPE,NULL,&action)!=0 || action.sa_handler!=host_handler) return 64;
 if(pthread_kill(pthread_self(),SIGPIPE)!=0) return 65;
 pthread_t worker;int failure=0;
 if(pthread_create(&worker,NULL,child,&failure)!=0 || pthread_join(worker,NULL)!=0) return 66;
 return failure;
}
int main(void) {
 struct sigaction action={0};action.sa_handler=host_handler;sigemptyset(&action.sa_mask);
 if(sigaction(SIGPIPE,&action,NULL)!=0) return 2;
 sigset_t pipe,mask;sigemptyset(&pipe);sigaddset(&pipe,SIGPIPE);
 if(pthread_sigmask(SIG_UNBLOCK,&pipe,NULL)!=0) return 3;
 const char *args[]={"tor"};uint64_t handle=0;
 if(routervpn_tor_start(args,1,&handle)!=0 || !handle) return 4;
 int status=0;int32_t code=0;
 for(int i=0;i<500 && status==0;i++) { struct timespec wait={0,1000000L};nanosleep(&wait,NULL);status=routervpn_tor_status(handle,&code); }
 if(routervpn_tor_close(handle,5000)!=0) return 5;
 if(status!=1 || code!=0) {fprintf(stderr,"Tor worker did not inherit protected signal mask: %d\n",code);return 6;}
 if(pthread_sigmask(SIG_SETMASK,NULL,&mask)!=0 || sigismember(&mask,SIGPIPE)!=0) return 7;
 if(sigaction(SIGPIPE,NULL,&action)!=0 || action.sa_handler!=host_handler || caught) return 8;
 puts("PASS shipping C owner preserves host signals and blocks SIGPIPE only in Tor/child threads");
 return 0;
}
'''

def check(source, expected, compiler, directory):
    binary = directory / ('signals-' + str(expected))
    command = [compiler, '-std=c11', '-Wall', '-Wextra', '-Werror', '-pthread', '-fsanitize=address,undefined',
               '-fno-omit-frame-pointer', '-I'+str(directory), '-I'+str(ROOT/'mobile/tor'), str(source),
               str(directory/'fixture.c'), '-o', str(binary)]
    subprocess.run(command, check=True)
    result = subprocess.run([binary], text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=15)
    if result.returncode != expected:
        raise RuntimeError('Tor thread signal ownership regression:\n'+result.stdout[-4000:])
    print(result.stdout.strip())

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cc',default=os.environ.get('CC','cc'))
    parser.add_argument('--original',type=Path)
    args=parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='routervpn-tor-signals-') as temporary:
        directory=Path(temporary)
        (directory/'tor_api.h').write_text(HEADER)
        (directory/'fixture.c').write_text(FIXTURE)
        if args.original:
            check(args.original.resolve(),6,args.cc,directory)
            print('PASS original host negative: Tor threads inherited unblocked SIGPIPE')
        check(ROOT/'mobile/tor/routervpn_tor_host.c',0,args.cc,directory)
if __name__=='__main__':main()
