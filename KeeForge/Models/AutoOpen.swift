import Foundation

/// One database a KeePassXC-style `AutoOpen` entry asks to open alongside the
/// database that holds it.
///
/// KeePassXC convention: entries in the root group's direct child named
/// `AutoOpen`. URL is the database path (`kdbx://` and `file://` prefixes
/// allowed, relative paths resolve against the holding database's folder,
/// `{DB_DIR}` expands to that folder), Password is its master password, and
/// UserName is an optional key file path. An entry needs a URL and at least one
/// of Password or UserName. `IfDevice` lists comma-separated device names; a
/// `!name` excludes that device and lets every other one through.
struct AutoOpenTarget: Identifiable, Sendable, Equatable {
    let id: UUID
    let title: String
    /// Absolute path when the holding database's folder is known, otherwise
    /// the path as written.
    let databasePath: String
    let keyFilePath: String?
    let hasPassword: Bool

    var databaseFilename: String { AutoOpen.lastPathComponent(databasePath) }
    var keyFileFilename: String? { keyFilePath.map(AutoOpen.lastPathComponent) }
}

/// An `AutoOpenTarget` matched to a database in KeeForge's list. KeeForge
/// cannot open an arbitrary path (sandbox, security-scoped bookmarks), so a
/// target is only usable once the user has added its file.
struct AutoOpenLink: Identifiable, Sendable, Equatable {
    let target: AutoOpenTarget
    let reference: DatabaseReference

    var id: UUID { target.id }
}

enum AutoOpen {
    static let groupName = "AutoOpen"
    static let deviceFieldName = "IfDevice"

    /// `rootGroup` is the parser's synthetic `<Root>`; KeePassXC's root group
    /// is the KDBX top-level group beneath it.
    static func group(in rootGroup: KPGroup) -> KPGroup? {
        rootGroup.groups.flatMap(\.groups).first { $0.name == groupName }
    }

    /// `resolve` expands field references in UserName and URL; it must be the
    /// read-side `FieldReferenceResolver`.
    static func targets(
        in rootGroup: KPGroup,
        databaseDirectory: String?,
        deviceName: String,
        now: Date = .now,
        resolve: (String) -> String = { $0 }
    ) -> [AutoOpenTarget] {
        guard let group = group(in: rootGroup) else { return [] }
        return group.entries.compactMap { entry in
            guard !entry.isExpired(at: now),
                  appliesToDevice(entry.customFields[deviceFieldName], deviceName: deviceName) else { return nil }
            let url = resolve(entry.url).trimmingCharacters(in: .whitespacesAndNewlines)
            let keyFile = resolve(entry.username).trimmingCharacters(in: .whitespacesAndNewlines)
            guard !url.isEmpty, entry.hasPassword || !keyFile.isEmpty,
                  let databasePath = resolvePath(url, databaseDirectory: databaseDirectory) else { return nil }
            return AutoOpenTarget(
                id: entry.id,
                title: entry.title,
                databasePath: databasePath,
                keyFilePath: keyFile.isEmpty ? nil : resolvePath(keyFile, databaseDirectory: databaseDirectory),
                hasPassword: entry.hasPassword
            )
        }
    }

    /// Matches by resolved path first. A path written on another computer
    /// rarely equals the local one, so a unique filename match is accepted too.
    static func links(
        for targets: [AutoOpenTarget],
        sourceID: UUID,
        references: [DatabaseReference],
        referencePaths: [UUID: String]
    ) -> [AutoOpenLink] {
        let candidates = references.filter { $0.id != sourceID }
        var linkedReferenceIDs = Set<UUID>()
        return targets.compactMap { target in
            let byPath = candidates.first { referencePaths[$0.id].map { ($0 as NSString).standardizingPath } == target.databasePath }
            let byName = candidates.filter { $0.filename.caseInsensitiveCompare(target.databaseFilename) == .orderedSame }
            guard let reference = byPath ?? (byName.count == 1 ? byName.first : nil),
                  linkedReferenceIDs.insert(reference.id).inserted else { return nil }
            return AutoOpenLink(target: target, reference: reference)
        }
    }

    /// Remote paths of cloud databases on the source's own account, so a
    /// relative target resolves against the source's remote folder. Paths on
    /// different accounts share no namespace and are left out.
    static func cloudPaths(source: DatabaseReference, references: [DatabaseReference]) -> [UUID: String] {
        guard let sourceMetadata = source.cloudSyncMetadata else { return [:] }
        var paths: [UUID: String] = [:]
        for reference in references + [source] {
            guard let metadata = reference.cloudSyncMetadata,
                  metadata.provider == sourceMetadata.provider,
                  metadata.accountId == sourceMetadata.accountId else { continue }
            paths[reference.id] = (metadata.displayPath as NSString).standardizingPath
        }
        return paths
    }

    static func lastPathComponent(_ path: String) -> String {
        path.split(whereSeparator: { $0 == "/" || $0 == "\\" }).last.map(String.init) ?? path
    }

    static func appliesToDevice(_ rule: String?, deviceName: String) -> Bool {
        let devices = (rule ?? "").split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
        guard !devices.isEmpty else { return true }
        var applies = false
        for device in devices {
            if device.hasPrefix("!") {
                if device.dropFirst().caseInsensitiveCompare(deviceName) == .orderedSame { return false }
                applies = true
            } else if device.caseInsensitiveCompare(deviceName) == .orderedSame {
                applies = true
            }
        }
        return applies
    }

    static func resolvePath(_ raw: String, databaseDirectory: String?) -> String? {
        var path = raw
        if let directory = databaseDirectory {
            path = path.replacingOccurrences(of: "{DB_DIR}", with: directory, options: .caseInsensitive)
        }
        if path.lowercased().hasPrefix("kdbx://") {
            path = String(path.dropFirst("kdbx://".count))
        }
        if path.lowercased().hasPrefix("file://") {
            guard let fileURL = URL(string: path), fileURL.isFileURL else { return nil }
            path = fileURL.path
        }
        guard !path.isEmpty else { return nil }
        if path.hasPrefix("/") || isWindowsAbsolute(path) { return (path as NSString).standardizingPath }
        guard let databaseDirectory else { return path }
        return ((databaseDirectory as NSString).appendingPathComponent(path) as NSString).standardizingPath
    }

    private static func isWindowsAbsolute(_ path: String) -> Bool {
        let scalars = Array(path.unicodeScalars.prefix(3))
        return scalars.count == 3 && CharacterSet.letters.contains(scalars[0]) && scalars[1] == ":" && (scalars[2] == "\\" || scalars[2] == "/")
    }
}
