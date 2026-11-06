package com.eabusham.routervpn;

import java.util.concurrent.CancellationException;
import javax.net.SocketFactory;
import org.json.JSONObject;

/** Home-node DNS queries, distinct from selected-policy native DNS proof. */
final class AndroidRouterDNSRetest {
    interface Request { JSONObject run(AndroidTelemetryIO io) throws Exception; }
    interface Callback { void finished(Job job, JSONObject result, Throwable error); }
    private static final Object ADMISSION = new Object();
    private static Job active;
    private static Object latestIdentity;
    private Job current;
    private boolean closed;

    static final class Job {
        final Object identity = new Object();
        final AndroidTelemetryIO io;
        volatile boolean cancelled;
        volatile boolean joined;
        JSONObject result;
        Throwable error;
        Thread worker;
        Job(AndroidTelemetryIO io) { this.io = io; }
    }

    synchronized Job start(AndroidNodeStore store, AndroidNodeStore.SelectionSnapshot source,
                           Request request, Callback callback) throws Exception {
        if (closed) throw new IllegalStateException("DNS settings are closed.");
        store.requireDNSBenchmarkSource(source);
        Job job = new Job(new AndroidTelemetryIO(SocketFactory.getDefault(),
                () -> store.requireDNSBenchmarkSource(source), 55000));
        job.worker = new Thread(() -> {
            try { job.io.attach(); job.io.check(); job.result = request.run(job.io); job.io.check(); }
            catch (Throwable failure) { job.error = failure; }
            finally { job.io.drain(); if (job.error == null) job.error = job.io.failure(); }
        }, "routervpn-home-dns-request");
        Thread completion = new Thread(() -> {
            boolean interrupted = false;
            while (job.worker.isAlive()) {
                try { job.worker.join(); } catch (InterruptedException ignored) { interrupted = true; }
            }
            job.joined = true;
            synchronized (ADMISSION) { if (active == job) active = null; }
            callback.finished(job, job.result, job.error);
            if (interrupted) Thread.currentThread().interrupt();
        }, "routervpn-home-dns-join");
        synchronized (ADMISSION) {
            if (active != null) throw new IllegalStateException("Another home DNS Retest is still running or draining.");
            active = job;
            latestIdentity = job.identity;
        }
        current = job;
        try { job.worker.start(); completion.start(); }
        catch (Throwable failure) {
            job.cancelled = true; job.io.cancel();
            // If the joiner could not start, retain admission until the actual
            // worker returns; never free a still-running request on cancellation.
            if (!completion.isAlive()) {
                boolean interrupted = false;
                while (job.worker.isAlive()) try { job.worker.join(); } catch (InterruptedException ignored) { interrupted = true; }
                job.joined = true;
                synchronized (ADMISSION) { if (active == job) active = null; }
                if (interrupted) Thread.currentThread().interrupt();
            }
            throw failure;
        }
        return job;
    }

    synchronized boolean visible(Job job) { return !closed && current == job; }
    synchronized void adopt(Job job, AndroidTelemetryIO.Check persist) throws Exception {
        synchronized (ADMISSION) {
            if (!visible(job) || latestIdentity != job.identity || job.cancelled || !job.joined || job.error != null)
                throw new CancellationException("DNS Retest was cancelled or superseded; measurement was not persisted.");
            // Admission and adoption share the latest operation identity even
            // after request drain. A delayed panel cannot commit over a newer job.
            persist.run();
        }
    }
    synchronized void cancel() { if (current != null) { current.cancelled = true; current.io.cancel(); } }
    synchronized void close() { closed = true; cancel(); }
}
