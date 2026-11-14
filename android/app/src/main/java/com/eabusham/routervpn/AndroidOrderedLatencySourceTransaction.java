package com.eabusham.routervpn;

/** History publication observes immutable original sources while holding the
 * existing Home/private-file transaction. It never enters source mutation
 * monitors, starts native proof work or changes connection selection. */
final class AndroidOrderedLatencySourceTransaction {
    interface Operation<T> { T run(AndroidNodeStore.HistoryReadback source) throws Exception; }

    static <T> T run(AndroidNodeStore.ChainCapture original, Operation<T> operation) throws Exception {
        if (original == null || operation == null) throw new IllegalStateException("The original history source transaction is missing.");
        synchronized (AndroidHomeStateStore.class) {
            synchronized (AndroidPrivateFileStore.class) {
                AndroidNodeStore.HistoryReadback source = original.historyReadback();
                try {
                    // Store.save owns all checks after the first write and its
                    // guarded rollback. Never throw a new check after it has
                    // successfully committed and left that rollback scope.
                    return operation.run(source);
                } finally {
                    source.close();
                }
            }
        }
    }

    private AndroidOrderedLatencySourceTransaction() {}
}
