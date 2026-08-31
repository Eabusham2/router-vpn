import Foundation

@MainActor
enum IOSPrivateJSONStore {
    private static let directoryName = "RouterVPNPrivate"

    static func read(_ filename: String, maximumBytes: Int) throws -> Data? {
        let url = try fileURL(filename)
        let manager = FileManager.default
        guard manager.fileExists(atPath: url.path) else { return nil }

        let values = try url.resourceValues(forKeys: [
            .isRegularFileKey,
            .isSymbolicLinkKey,
            .fileSizeKey,
        ])
        guard values.isRegularFile == true, values.isSymbolicLink != true else {
            throw issue("Private state is not a regular file.")
        }
        let size = values.fileSize ?? 0
        guard size > 0, size <= maximumBytes else {
            throw issue("Private state has an invalid size.")
        }

        let data = try Data(contentsOf: url, options: [.mappedIfSafe])
        guard !data.isEmpty, data.count <= maximumBytes else {
            throw issue("Private state has an invalid size.")
        }
        return data
    }

    static func write(_ data: Data, filename: String, maximumBytes: Int) throws {
        guard !data.isEmpty, data.count <= maximumBytes else {
            throw issue("Private state has an invalid size.")
        }

        let destination = try fileURL(filename)
        let manager = FileManager.default
        if manager.fileExists(atPath: destination.path) {
            let values = try destination.resourceValues(forKeys: [.isRegularFileKey, .isSymbolicLinkKey])
            guard values.isRegularFile == true, values.isSymbolicLink != true else {
                throw issue("Private state destination is unsafe.")
            }
        }

        let temporary = destination.deletingLastPathComponent()
            .appendingPathComponent(".\(filename).\(UUID().uuidString.lowercased()).tmp", isDirectory: false)
        let attributes: [FileAttributeKey: Any] = [
            .posixPermissions: NSNumber(value: Int16(0o600)),
            .protectionKey: FileProtectionType.completeUntilFirstUserAuthentication,
        ]

        guard manager.createFile(atPath: temporary.path, contents: nil, attributes: attributes) else {
            throw issue("Could not create private temporary state.")
        }

        var adopted = false
        defer {
            if !adopted { try? manager.removeItem(at: temporary) }
        }

        let handle = try FileHandle(forWritingTo: temporary)
        do {
            try handle.write(contentsOf: data)
            try handle.synchronize()
            try handle.close()
        } catch {
            try? handle.close()
            throw error
        }
        try manager.setAttributes(attributes, ofItemAtPath: temporary.path)

        if manager.fileExists(atPath: destination.path) {
            _ = try manager.replaceItemAt(destination, withItemAt: temporary, backupItemName: nil, options: [])
        } else {
            try manager.moveItem(at: temporary, to: destination)
        }
        adopted = true
        try manager.setAttributes(attributes, ofItemAtPath: destination.path)

        var directory = destination.deletingLastPathComponent()
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        try? directory.setResourceValues(values)
    }

    static func remove(_ filename: String) throws {
        let url = try fileURL(filename)
        let manager = FileManager.default
        guard manager.fileExists(atPath: url.path) else { return }
        let values = try url.resourceValues(forKeys: [.isRegularFileKey, .isSymbolicLinkKey])
        guard values.isRegularFile == true, values.isSymbolicLink != true else {
            throw issue("Private state destination is unsafe.")
        }
        try manager.removeItem(at: url)
    }

    private static func fileURL(_ filename: String) throws -> URL {
        guard !filename.isEmpty,
              filename.count <= 96,
              filename.unicodeScalars.allSatisfy({ scalar in
                  CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-").contains(scalar)
              }) else {
            throw issue("Private state filename is invalid.")
        }

        let manager = FileManager.default
        let base = try manager.url(
            for: .applicationSupportDirectory,
            in: .userDomainMask,
            appropriateFor: nil,
            create: true
        )
        let directory = base.appendingPathComponent(directoryName, isDirectory: true)
        try manager.createDirectory(
            at: directory,
            withIntermediateDirectories: true,
            attributes: [
                .posixPermissions: NSNumber(value: Int16(0o700)),
                .protectionKey: FileProtectionType.completeUntilFirstUserAuthentication,
            ]
        )
        try manager.setAttributes(
            [
                .posixPermissions: NSNumber(value: Int16(0o700)),
                .protectionKey: FileProtectionType.completeUntilFirstUserAuthentication,
            ],
            ofItemAtPath: directory.path
        )
        return directory.appendingPathComponent(filename, isDirectory: false)
    }

    private static func issue(_ message: String) -> NSError {
        NSError(
            domain: "RouterVPN.PrivateJSONStore",
            code: 1,
            userInfo: [NSLocalizedDescriptionKey: message]
        )
    }
}
