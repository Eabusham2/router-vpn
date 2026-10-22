package com.eabusham.routervpn;

import java.net.URI;

/** Read-only UI receipt, tied to the exact installed source that was checked. */
final class AndroidUpdateSnapshot {
    static final long MAX_AGE_MS = 24L * 60L * 60L * 1000L;
    final String installed, target, apkURL, apkDigest;
    final long apkBytes, verifiedAt;

    private AndroidUpdateSnapshot(String installed, String target, String apkURL, long apkBytes, String digest, long at) {
        this.installed=installed;this.target=target;this.apkURL=apkURL;this.apkBytes=apkBytes;apkDigest=digest;verifiedAt=at;
    }

    static AndroidUpdateSnapshot verified(String installed, String checkedFrom, String target, String url,
                                          long bytes, String digest, long at, boolean verified, long now) {
        if (!verified || installed == null || !installed.matches("[0-9a-f]{40}") || !installed.equals(checkedFrom)
                || target == null || !target.matches("[0-9a-f]{40}") || target.equals(installed)
                || digest == null || !digest.matches("[0-9a-f]{64}") || bytes <= 0 || bytes > 768L*1024L*1024L
                || at <= 0 || now < at || now-at > MAX_AGE_MS || url == null) return null;
        String expected="https://github.com/Eabusham2/router-vpn/releases/download/router-vpn-sha-"+target+"/app-debug.apk";
        try {
            URI uri=new URI(url);
            if (!expected.equals(url) || uri.getUserInfo()!=null || uri.getPort()!=-1 || uri.getQuery()!=null || uri.getFragment()!=null) return null;
        } catch (Exception invalid) { return null; }
        return new AndroidUpdateSnapshot(installed,target,url,bytes,digest,at);
    }
}
