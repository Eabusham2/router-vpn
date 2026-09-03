package com.eabusham.routervpn;

import android.system.ErrnoException;
import android.system.Os;
import android.system.OsConstants;
import android.system.StructStat;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.SecureRandom;
import java.util.Locale;

/** Shared app-private regular-file primitive for authoritative Android state. */
final class AndroidPrivateFileStore {
    private static final SecureRandom RANDOM = new SecureRandom();

    static void ensurePrivateDirectory(File directory) throws Exception {
        if (directory == null) throw new IllegalStateException("Private state directory is unavailable.");
        if (!directory.exists() && !directory.mkdirs()) throw new IllegalStateException("Cannot create private state directory.");
        StructStat stat = Os.lstat(directory.getAbsolutePath());
        if ((stat.st_mode & OsConstants.S_IFMT) != OsConstants.S_IFDIR) {
            throw new IllegalStateException("Private state parent is not a directory.");
        }
        Os.chmod(directory.getAbsolutePath(), 0700);
        StructStat after = Os.lstat(directory.getAbsolutePath());
        if ((after.st_mode & OsConstants.S_IFMT) != OsConstants.S_IFDIR || (after.st_mode & 0077) != 0) {
            throw new IllegalStateException("Private state directory permissions are unsafe.");
        }
    }

    static byte[] read(File target, int maximumBytes) throws Exception {
        if (target == null || maximumBytes <= 0) throw new IllegalArgumentException("Private state read limit is invalid.");
        StructStat before = requirePrivateRegular(target, maximumBytes, true);
        try (FileInputStream in = new FileInputStream(target); ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            StructStat opened = Os.fstat(in.getFD());
            StructStat current = Os.lstat(target.getAbsolutePath());
            requireSameRegularFile(target, opened, current);
            if (opened.st_dev != before.st_dev || opened.st_ino != before.st_ino) {
                throw new IllegalStateException("Private state changed while opening.");
            }
            byte[] buffer = new byte[8192];
            int total = 0, count;
            while ((count = in.read(buffer)) != -1) {
                total += count;
                if (total > maximumBytes) throw new IllegalStateException("Private state exceeds safety limit.");
                out.write(buffer, 0, count);
            }
            if (total <= 0) throw new IllegalStateException("Private state is empty.");
            return out.toByteArray();
        }
    }

    static void write(File target, byte[] bytes, int maximumBytes) throws Exception {
        if (target == null || bytes == null || bytes.length <= 0 || bytes.length > maximumBytes) {
            throw new IllegalArgumentException("Private state payload is invalid.");
        }
        File parent = target.getParentFile();
        ensurePrivateDirectory(parent);
        StructStat targetBefore = optionalPrivateRegular(target, maximumBytes);
        File temporary = new File(parent, "." + target.getName() + "." + randomHex(12) + ".tmp");
        boolean adopted = false;
        try {
            if (!temporary.createNewFile()) throw new IllegalStateException("Cannot create private state temporary file.");
            Os.chmod(temporary.getAbsolutePath(), 0600);
            try (FileOutputStream out = new FileOutputStream(temporary, false)) {
                out.write(bytes);
                out.flush();
                out.getFD().sync();
            }
            requirePrivateRegular(temporary, maximumBytes, false);
            ensurePrivateDirectory(parent);
            requireTargetUnchanged(target, targetBefore, maximumBytes);
            Os.rename(temporary.getAbsolutePath(), target.getAbsolutePath());
            adopted = true;
            // The verified 0600 temporary inode is now authoritative. Do not
            // perform a fallible chmod/stat after commit and report a false
            // failure to callers whose in-memory state may then roll back.
        } finally {
            if (!adopted && temporary.exists() && !temporary.delete()) temporary.deleteOnExit();
        }
    }

    static void remove(File target, int maximumBytes) throws Exception {
        if (target == null) return;
        try {
            StructStat before = requirePrivateRegular(target, maximumBytes, true);
            StructStat current = Os.lstat(target.getAbsolutePath());
            requireSameRegularFile(target, before, current);
            Os.remove(target.getAbsolutePath());
        } catch (ErrnoException error) {
            if (error.errno != OsConstants.ENOENT) throw error;
        }
    }

    private static StructStat optionalPrivateRegular(File target, int maximumBytes) throws Exception {
        try {
            return requirePrivateRegular(target, maximumBytes, true);
        } catch (ErrnoException error) {
            if (error.errno == OsConstants.ENOENT) return null;
            throw error;
        }
    }

    private static StructStat requirePrivateRegular(File target, int maximumBytes, boolean requireNonEmpty) throws Exception {
        StructStat stat = Os.lstat(target.getAbsolutePath());
        if ((stat.st_mode & OsConstants.S_IFMT) != OsConstants.S_IFREG) {
            throw new IllegalStateException("Private state is not a regular file.");
        }
        if ((stat.st_mode & 0077) != 0) {
            Os.chmod(target.getAbsolutePath(), 0600);
            stat = Os.lstat(target.getAbsolutePath());
        }
        if ((stat.st_mode & OsConstants.S_IFMT) != OsConstants.S_IFREG || (stat.st_mode & 0077) != 0) {
            throw new IllegalStateException("Private state permissions are unsafe.");
        }
        if ((requireNonEmpty && stat.st_size <= 0) || stat.st_size > maximumBytes) {
            throw new IllegalStateException("Private state size is invalid.");
        }
        return stat;
    }

    private static void requireTargetUnchanged(File target, StructStat before, int maximumBytes) throws Exception {
        StructStat current = optionalPrivateRegular(target, maximumBytes);
        if (before == null) {
            if (current != null) throw new IllegalStateException("Private state appeared before adoption.");
            return;
        }
        if (current == null || before.st_dev != current.st_dev || before.st_ino != current.st_ino) {
            throw new IllegalStateException("Private state identity changed before adoption.");
        }
    }

    private static void requireSameRegularFile(File target, StructStat left, StructStat right) {
        if ((left.st_mode & OsConstants.S_IFMT) != OsConstants.S_IFREG
                || (right.st_mode & OsConstants.S_IFMT) != OsConstants.S_IFREG
                || left.st_dev != right.st_dev || left.st_ino != right.st_ino) {
            throw new IllegalStateException("Private state changed during access: " + target.getName());
        }
    }

    private static String randomHex(int bytes) {
        byte[] value = new byte[bytes]; RANDOM.nextBytes(value);
        StringBuilder out = new StringBuilder(bytes * 2);
        for (byte item : value) out.append(String.format(Locale.ROOT, "%02x", item & 255));
        return out.toString();
    }

    private AndroidPrivateFileStore() { }
}
