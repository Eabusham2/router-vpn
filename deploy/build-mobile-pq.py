#!/usr/bin/env python3
"""Build the pinned, socket-free Rosenpass C ABI for native mobile hosts."""
from __future__ import annotations
import argparse, hashlib, json, os, platform, plistlib, shutil, subprocess, sys, tempfile
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
SOURCE=ROOT/'mobile/rosenpass'
RUST='1.99.0'
NDK='28.0.13004108'
ANDROID=(('arm64-v8a','aarch64-linux-android','aarch64-linux-android'),('armeabi-v7a','armv7-linux-androideabi','armv7a-linux-androideabi'),('x86','i686-linux-android','i686-linux-android'),('x86_64','x86_64-linux-android','x86_64-linux-android'))
APPLE=(('aarch64-apple-ios','iphoneos','arm64'),('aarch64-apple-ios-sim','iphonesimulator','arm64'),('x86_64-apple-ios','iphonesimulator','x86_64'))

def ensure_python():
    """Xcode can replace PATH with Apple's older system Python during a build.

    Find an installed interpreter with the real stdlib TOML parser before any
    cache validation or output mutation. Never install packages or approximate
    lockfile parsing to make an incompatible interpreter appear supported.
    """
    if sys.version_info >= (3, 11):
        return
    explicit = os.environ.get('ROUTER_VPN_PYTHON', '').strip()
    candidates = [explicit] if explicit else [
        'python3', 'python3.15', 'python3.14', 'python3.13', 'python3.12', 'python3.11',
        '/opt/homebrew/bin/python3', '/usr/local/bin/python3',
    ]
    seen = {str(Path(sys.executable).resolve())}
    for candidate in candidates:
        executable = shutil.which(candidate)
        if not executable:
            continue
        executable = str(Path(executable).resolve())
        if executable in seen:
            continue
        seen.add(executable)
        try:
            result = subprocess.run(
                [executable, '-I', '-c', 'import sys, tomllib; assert sys.version_info >= (3, 11)'],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5,
            )
        except (OSError, subprocess.TimeoutExpired):
            continue
        if result.returncode == 0:
            os.execv(executable, [executable, '-I', str(Path(__file__).resolve()), *sys.argv[1:]])
            raise RuntimeError('Native PQ Python replacement unexpectedly returned')
    raise RuntimeError('Native PQ requires Python 3.11+ with tomllib; set ROUTER_VPN_PYTHON to its executable')

def run(args, *, env=None, capture=False):
    return subprocess.run([str(x) for x in args],env=env,check=True,text=True,stdout=subprocess.PIPE if capture else None).stdout

def source_digest():
    paths=[Path(__file__).resolve(),*sorted(SOURCE.glob('*.toml')),*sorted(SOURCE.glob('*.lock')),*sorted(SOURCE.glob('*.h')),*sorted(SOURCE.glob('*.c')),*sorted((SOURCE/'src').rglob('*.rs'))]
    digest=hashlib.sha256()
    for path in sorted(set(paths)):
        digest.update(str(path.relative_to(ROOT)).encode()+b'\0'+path.read_bytes()+b'\0')
    return digest.hexdigest()

def validate_lock():
    import tomllib
    lock=tomllib.loads((SOURCE/'Cargo.lock').read_text())
    assert lock['version']>=3
    for package in lock['package']:
        source=package.get('source','')
        if source.startswith('registry+'):
            checksum=package.get('checksum','');assert len(checksum)==64 and all(c in '0123456789abcdef' for c in checksum)
        elif source.startswith('git+'):
            commit=source.rsplit('#',1)[-1]
            assert len(commit)==40 and '?rev='+commit+'#'+commit in source,'Unpinned Git dependency'
    return hashlib.sha256((SOURCE/'Cargo.lock').read_bytes()).hexdigest()

def verify(output, kind, digest):
    try:
        meta=json.loads((output/'source.json').read_text())
        if meta['schema']!=1 or meta['source_sha256']!=digest or meta['platform']!=kind or meta['rust']!=RUST or meta['cargo_lock_sha256']!=validate_lock():return False
        expected=set(meta['files'])
        actual={str(p.relative_to(output)) for p in output.rglob('*') if p.is_file() and p.name!='source.json'}
        if expected!=actual:return False
        for relative,wanted in meta['files'].items():
            p=output/relative
            if '..' in Path(relative).parts or Path(relative).is_absolute() or p.is_symlink() or hashlib.sha256(p.read_bytes()).hexdigest()!=wanted:return False
        if kind=='android':
            if not all(f'jni/{abi}/libroutervpn_rosenpass_jni.so' in actual for abi,_,_ in ANDROID):return False
        else:
            meta=plistlib.loads((output/'RouterVPNPQ.xcframework/Info.plist').read_bytes())
            libs=meta['AvailableLibraries']
            slices={(x['SupportedPlatform'],x.get('SupportedPlatformVariant','')):set(x['SupportedArchitectures']) for x in libs}
            if slices!={('ios',''):{'arm64'},('ios','simulator'):{'arm64','x86_64'}}:return False
        return True
    except (OSError,ValueError,KeyError,AssertionError):return False

def ensure_tools(targets):
    for tool in ('rustup','cmake','ninja','clang'):
        if not shutil.which(tool):raise RuntimeError(f'{tool} is required for the pinned native PQ build')
    run(['rustup','toolchain','install',RUST,'--profile','minimal','--no-self-update'])
    run(['rustup','target','add','--toolchain',RUST,*targets])
    assert run(['rustc','+'+RUST,'--version'],capture=True).startswith('rustc '+RUST+' ')

def base_env(cache):
    env=os.environ.copy()
    # Do not inherit the Apple libbox builder's ambient CGO/target selection.
    for key in ('CC','CXX','AR','CFLAGS','CXXFLAGS','SDKROOT','CMAKE_TOOLCHAIN_FILE','CARGO_ENCODED_RUSTFLAGS'):
        env.pop(key,None)
    env.update(CARGO_TARGET_DIR=str(cache),CARGO_BUILD_JOBS=env.get('CARGO_BUILD_JOBS','2'),CARGO_INCREMENTAL='0',CMAKE_GENERATOR='Ninja',OQS_PERMIT_UNSUPPORTED_ARCHITECTURE='ON',RUSTFLAGS='-C relocation-model=pic')
    return env

def cargo(target,env):
    before=validate_lock()
    run(['cargo','+'+RUST,'build','--locked','--manifest-path',SOURCE/'Cargo.toml','--target',target,'--release'],env=env)
    assert validate_lock()==before,'Cargo mutated the dependency lock'
    lib=Path(env['CARGO_TARGET_DIR'])/target/'release/libroutervpn_rosenpass.a'
    if not lib.is_file() or lib.stat().st_size==0:raise RuntimeError('Native Rust archive is missing')
    return lib

def android_build(stage,cache):
    sdk=Path(os.environ.get('ANDROID_HOME') or os.environ.get('ANDROID_SDK_ROOT') or '/missing-android-sdk')
    ndk=sdk/'ndk'/NDK
    if not (ndk/'source.properties').is_file():
        manager=sdk/'cmdline-tools/latest/bin/sdkmanager'
        if not manager.is_file():raise RuntimeError('Android sdkmanager is required')
        run([manager,'ndk;'+NDK])
    assert 'Pkg.Revision = '+NDK in (ndk/'source.properties').read_text(),'Wrong Android NDK'
    host='darwin-x86_64' if platform.system()=='Darwin' else 'linux-x86_64'
    tools=ndk/'toolchains/llvm/prebuilt'/host
    for abi,target,triple in ANDROID:
        env=base_env(cache);cc=tools/'bin'/(triple+'24-clang');ar=tools/'bin/llvm-ar'
        if not cc.is_file():raise RuntimeError('Missing pinned target compiler: '+str(cc))
        toolchain=stage/(abi+'.cmake')
        toolchain.write_text(f'set(ANDROID_ABI "{abi}" CACHE STRING "" FORCE)\nset(ANDROID_PLATFORM android-24 CACHE STRING "" FORCE)\nset(ANDROID_STL c++_static CACHE STRING "" FORCE)\ninclude("{ndk}/build/cmake/android.toolchain.cmake")\n')
        env.update(ANDROID_NDK_HOME=str(ndk),ANDROID_NDK_ROOT=str(ndk),CMAKE_TOOLCHAIN_FILE=str(toolchain),BINDGEN_EXTRA_CLANG_ARGS=f'--target={triple}24 --sysroot={tools}/sysroot')
        env['CC_'+target.replace('-','_')]=str(cc);env['AR_'+target.replace('-','_')]=str(ar)
        env['CARGO_TARGET_'+target.replace('-','_').upper()+'_LINKER']=str(cc)
        rust=cargo(target,env)
        out=stage/'jni'/abi/'libroutervpn_rosenpass_jni.so';out.parent.mkdir(parents=True,exist_ok=True)
        run([cc,'-std=c11','-O2','-fPIC','-fvisibility=hidden','-Wall','-Wextra','-Werror','-shared',
             '-Wl,--no-undefined','-Wl,--exclude-libs,ALL','-Wl,-z,max-page-size=16384','-Wl,-z,common-page-size=16384','-Wl,-soname,libroutervpn_rosenpass_jni.so',
             SOURCE/'routervpn_pq_host.c',SOURCE/'routervpn_pq_jni.c',rust,'-ldl','-lm','-llog','-latomic','-o',out],env=env)
        symbols=run([tools/'bin/llvm-nm','-D','--defined-only',out],capture=True)
        for symbol in ('nativeABI','nativeOpen','nativeEvent','nativeClose'):
            assert 'Java_com_eabusham_routervpn_RouterPQNative_'+symbol in symbols
        toolchain.unlink()

def apple_build(stage,cache):
    if platform.system()!='Darwin':raise RuntimeError('Apple SDK builds require macOS/Xcode')
    headers=stage/'headers';headers.mkdir()
    for name in ('routervpn_rosenpass.h','routervpn_pq_host.h'):shutil.copyfile(SOURCE/name,headers/name)
    (headers/'module.modulemap').write_text('module RouterVPNPQ {\n header "routervpn_rosenpass.h"\n header "routervpn_pq_host.h"\n export *\n}\n')
    built={}
    for target,sdk,arch in APPLE:
        env=base_env(cache)
        sdkroot=run(['xcrun','--sdk',sdk,'--show-sdk-path'],capture=True).strip()
        clang=run(['xcrun','--sdk',sdk,'--find','clang'],capture=True).strip()
        triple=arch+'-apple-ios17.0'+('-simulator' if sdk=='iphonesimulator' else '')
        toolchain=stage/(target+'.cmake')
        toolchain.write_text(f'set(CMAKE_SYSTEM_NAME iOS)\nset(CMAKE_OSX_SYSROOT "{sdkroot}" CACHE PATH "" FORCE)\nset(CMAKE_OSX_ARCHITECTURES {arch} CACHE STRING "" FORCE)\nset(CMAKE_OSX_DEPLOYMENT_TARGET 17.0 CACHE STRING "" FORCE)\nset(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)\n')
        env.update(SDKROOT=sdkroot,IPHONEOS_DEPLOYMENT_TARGET='17.0',CMAKE_TOOLCHAIN_FILE=str(toolchain),BINDGEN_EXTRA_CLANG_ARGS=f'-target {triple} -isysroot {sdkroot}')
        env['CC_'+target.replace('-','_')]=clang
        env['CFLAGS_'+target.replace('-','_')]=f'-target {triple} -isysroot {sdkroot} -fPIC'
        rust=cargo(target,env)
        obj=stage/(target+'.o');lib=stage/(target+'.a')
        run([clang,'-target',triple,'-isysroot',sdkroot,'-std=c11','-O2','-fPIC','-Wall','-Wextra','-Werror','-c',SOURCE/'routervpn_pq_host.c','-o',obj],env=env)
        run(['xcrun','libtool','-static','-o',lib,obj,rust]);built[target]=lib
        obj.unlink();toolchain.unlink()
    simulator=stage/'simulator.a'
    run(['xcrun','lipo','-create',built['aarch64-apple-ios-sim'],built['x86_64-apple-ios'],'-output',simulator])
    run(['xcodebuild','-create-xcframework','-library',built['aarch64-apple-ios'],'-headers',headers,'-library',simulator,'-headers',headers,'-output',stage/'RouterVPNPQ.xcframework'])
    for path in built.values():path.unlink()
    simulator.unlink();shutil.rmtree(headers)

def output_state(output, kind):
    """Accept a missing/empty task output or a manifest-owned artifact tree.

    Gradle may create output directories before Exec runs. A symlink or an
    unknown file is not an empty task output and is never removed by this build.
    Old generated bytes may be corrupt (the reason for rebuilding), but the
    manifest must still name the complete, confined set of files we own.
    """
    fail = RuntimeError('Refusing to replace an unowned native PQ output directory')
    if output.is_symlink():
        raise fail
    if not output.exists():
        return 'missing'
    if not output.is_dir():
        raise fail
    paths = list(output.rglob('*'))
    if any(p.is_symlink() or not (p.is_file() or p.is_dir()) for p in paths):
        raise fail
    actual = {str(p.relative_to(output)) for p in paths if p.is_file()}
    if not actual:
        return 'empty'
    try:
        meta = json.loads((output/'source.json').read_text())
        files = meta['files']
        if meta['schema'] != 1 or meta['platform'] != kind or not isinstance(files, dict) or not files:
            raise fail
        if actual != set(files) | {'source.json'}:
            raise fail
        for name, digest in files.items():
            path = Path(name)
            if path.is_absolute() or '..' in path.parts or str(path) != name or not path.parts:
                raise fail
            if not isinstance(digest, str) or len(digest) != 64 or any(c not in '0123456789abcdef' for c in digest):
                raise fail
            if kind == 'android':
                allowed = {f'jni/{abi}/libroutervpn_rosenpass_jni.so' for abi, _, _ in ANDROID}
                if name not in allowed:
                    raise fail
            elif path.parts[0] != 'RouterVPNPQ.xcframework':
                raise fail
    except (OSError, ValueError, KeyError, TypeError):
        raise fail from None
    return 'owned'


def publish_output(stage, output, kind):
    state = output_state(output, kind)
    if state == 'empty':
        # rmdir fails rather than deleting a file added after the preflight.
        for path in sorted(output.rglob('*'), key=lambda p: len(p.parts), reverse=True):
            path.rmdir()
        output.rmdir()
        state = 'missing'
    if state == 'missing':
        os.replace(stage, output)
        return
    backup = Path(tempfile.mkdtemp(prefix='.routervpn-pq-previous-', dir=output.parent))
    backup.rmdir()
    os.replace(output, backup)
    try:
        os.replace(stage, output)
    except BaseException:
        # Never clear an unexpected destination to force a rollback. If another
        # actor created one, replace refuses and the original remains in backup.
        os.replace(backup, output)
        raise
    shutil.rmtree(backup)


def build(kind,output):
    output=output.parent.resolve()/output.name
    output_state(output, kind)
    digest=source_digest();validate_lock()
    if verify(output,kind,digest):
        print('Exact native PQ package already verified:',kind,digest);return
    targets=[x[1] for x in ANDROID] if kind=='android' else [x[0] for x in APPLE]
    ensure_tools(targets)
    output.parent.mkdir(parents=True,exist_ok=True)
    cache=output.parent/'.routervpn-pq-cargo';cache.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.routervpn-pq-stage-',dir=output.parent) as work:
        stage=Path(work)
        (android_build if kind=='android' else apple_build)(stage,cache)
        meta={'schema':1,'platform':kind,'source_sha256':digest,'cargo_lock_sha256':validate_lock(),'rust':RUST,'ndk':NDK if kind=='android' else None,
              'files':{str(p.relative_to(stage)):hashlib.sha256(p.read_bytes()).hexdigest() for p in stage.rglob('*') if p.is_file()}}
        (stage/'source.json').write_text(json.dumps(meta,sort_keys=True,indent=2)+'\n')
        if not verify(stage,kind,digest):raise RuntimeError('Native PQ artifact verification failed')
        publish_output(stage, output, kind)
    print('Native PQ package built and hash-verified:',kind,digest)

if __name__=='__main__':
    ensure_python()
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--platform',choices=('android','ios'))
    parser.add_argument('--output',type=Path)
    parser.add_argument('--digest',action='store_true')
    args=parser.parse_args()
    if args.digest:print(source_digest())
    else:
        if not args.platform or not args.output:parser.error('--platform and --output are required')
        build(args.platform,args.output)
