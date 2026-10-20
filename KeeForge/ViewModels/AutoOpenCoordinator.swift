import CryptoKit
import Foundation
#if os(iOS)
import UIKit
#endif

/// The master password and key file an `AutoOpenLink` opens its database with.
/// Read from the source session just before use and never stored.
struct AutoOpenCredentials: Sendable {
    let password: String
    let keyFileData: Data?
}

/// KeePassXC-style Auto Open on top of one-session-at-a-time KeeForge: finds
/// the databases a session's `AutoOpen` group links to, and primes each one
/// for AutoFill (Keychain quick-unlock key, shared cached copy, credential
/// identities) as an unlock of that database would.
@MainActor
enum AutoOpenCoordinator {
    /// KeePassXC matches `IfDevice` against the host name. iOS reports a
    /// generic model name without a special entitlement.
    static var deviceName: String {
        #if os(macOS)
        var buffer = [CChar](repeating: 0, count: 256)
        guard gethostname(&buffer, buffer.count) == 0 else { return "" }
        let hostName = String(cString: buffer)
        return hostName.hasSuffix(".local") ? String(hostName.dropLast(".local".count)) : hostName
        #else
        UIDevice.current.name
        #endif
    }

    static func links(
        in rootGroup: KPGroup,
        source: DatabaseReference,
        references: [DatabaseReference],
        deviceName: String,
        resolve: @Sendable (String) -> String
    ) async -> [AutoOpenLink] {
        guard AutoOpen.group(in: rootGroup) != nil else { return [] }
        let localPaths = await resolvedPaths(of: [source] + references.filter { $0.id != source.id })
        let paths = localPaths.merging(AutoOpen.cloudPaths(source: source, references: references)) { local, _ in local }
        let targets = AutoOpen.targets(
            in: rootGroup,
            databaseDirectory: paths[source.id].map { ($0 as NSString).deletingLastPathComponent },
            deviceName: deviceName,
            resolve: resolve
        )
        return AutoOpen.links(for: targets, sourceID: source.id, references: references, referencePaths: paths)
    }

    /// Adds the databases the source links to but the list lacks, where
    /// KeeForge can reach them without a file picker: WebDAV and FTP files on
    /// the source's account, and top-level files in the app's Documents folder
    /// beside a source stored there. Cloud copies are downloaded so the new
    /// links can be primed like any other.
    static func addMissingDatabases(
        in rootGroup: KPGroup,
        source: DatabaseReference,
        linked: [AutoOpenLink],
        deviceName: String,
        resolve: @Sendable (String) -> String
    ) async -> [AutoOpenLink] {
        var sourcePath = source.cloudSyncMetadata.map { ($0.displayPath as NSString).standardizingPath }
        if source.isCloudBacked == false {
            sourcePath = await resolvedPaths(of: [source])[source.id]
        }
        guard let sourcePath else { return [] }
        let targets = AutoOpen.targets(
            in: rootGroup,
            databaseDirectory: (sourcePath as NSString).deletingLastPathComponent,
            deviceName: deviceName,
            resolve: resolve
        )
        var knownIDs = Set(linked.map(\.reference.id) + [source.id])
        var added: [AutoOpenLink] = []
        for target in targets where linked.contains(where: { $0.target.id == target.id }) == false {
            guard Task.isCancelled == false else { break }
            let reference: DatabaseReference?
            if source.isCloudBacked {
                reference = await addCloudDatabase(for: target, source: source)
            } else {
                reference = addDocumentsDatabase(for: target, sourcePath: sourcePath)
            }
            guard let reference, knownIDs.insert(reference.id).inserted else { continue }
            added.append(AutoOpenLink(target: target, reference: reference))
        }
        return added
    }

    private static func addCloudDatabase(for target: AutoOpenTarget, source: DatabaseReference) async -> DatabaseReference? {
        guard let metadata = source.cloudSyncMetadata,
              let provider = CloudProviderRegistry.provider(for: metadata.provider),
              provider.isAuthenticated(accountId: metadata.accountId) else { return nil }
        for file in AutoOpen.cloudCandidates(for: target, source: source) {
            guard (try? await provider.getMetadata(accountId: metadata.accountId, fileId: file.id)) != nil else { continue }
            let reference = DatabaseListStore.addCloud(provider: metadata.provider, accountId: metadata.accountId, file: file)
            guard let resolution = try? await CloudSyncCoordinator.syncIfNeededForOpen(
                reference: reference,
                allowCachedFallback: false
            ) else { return reference }
            DatabaseListStore.update(resolution.reference)
            return resolution.reference
        }
        return nil
    }

    private static func addDocumentsDatabase(for target: AutoOpenTarget, sourcePath: String) -> DatabaseReference? {
        let sourceURL = URL(fileURLWithPath: sourcePath)
        let url = sourceURL.deletingLastPathComponent().appendingPathComponent(target.databaseFilename, isDirectory: false)
        guard DatabaseListStore.isTopLevelDocumentsFile(sourceURL),
              url.standardizedFileURL != sourceURL.standardizedFileURL,
              FileManager.default.fileExists(atPath: url.path) else { return nil }
        return try? DatabaseListStore.add(url: url)
    }

    /// Bookmark resolution touches the file system, so it stays off the main actor.
    private static func resolvedPaths(of references: [DatabaseReference]) async -> [UUID: String] {
        let localReferences = references.filter { $0.isCloudBacked == false && $0.bookmarkData != nil }
        return await Task.detached(priority: .utility) {
            var paths: [UUID: String] = [:]
            for reference in localReferences {
                if case .available(let url) = DatabaseListStore.locateDatabaseFile(for: reference) {
                    paths[reference.id] = url.path
                }
            }
            return paths
        }.value
    }

    /// The linked database's own associated key file. The path in the
    /// `AutoOpen` entry is not readable from the sandbox.
    static func keyFileData(for reference: DatabaseReference) async -> Data? {
        try? await CoordinatedFileReader.performBlocking(timeout: .seconds(10)) { () -> Data? in
            guard let url = DatabaseListStore.resolveKeyFileURL(for: reference) else { return nil }
            let hasSecurityScope = url.startAccessingSecurityScopedResource()
            defer {
                if hasSecurityScope {
                    url.stopAccessingSecurityScopedResource()
                }
            }
            return try? CoordinatedFileReader.readData(from: url)
        }
    }

    /// Verifies the credentials by decrypting the linked database, then leaves
    /// behind exactly what its own unlock would for AutoFill. Failures are
    /// silent: the user still sees them when opening the link.
    static func primeForAutoFill(_ link: AutoOpenLink, credentials: AutoOpenCredentials) async {
        guard let reference = DatabaseListStore.databases.first(where: { $0.id == link.reference.id }),
              reference.hardwareKey == nil else { return }
        do {
            let data = try await databaseData(for: reference)
            let compositeKey = try KDBXCrypto.compositeKey(password: credentials.password, keyFileData: credentials.keyFileData)
            let rootGroup = try await Task.detached(priority: .utility) {
                try KDBXParser.parseWithMetaAndHeader(
                    data: data,
                    compositeKey: compositeKey,
                    sessionKey: SymmetricKey(size: .bits256),
                    kdfPolicy: .mainApp
                ).rootGroup
            }.value

            if reference.isCloudBacked == false, PendingLocalSaveStore.hasSaves(for: reference.id) == false {
                try? DatabaseListStore.cacheDatabaseCopy(data, for: reference)
            }
            if KeychainService.shouldStoreQuickUnlockKey(for: reference.id, legacyFilename: reference.legacyKeychainFilename) {
                try? KeychainService.storeCompositeKey(compositeKey, for: reference.id)
            }
            if SettingsService.quickAutoFillEnabled, reference.autoFillEnabled {
                CredentialIdentityStoreManager.populate(
                    with: DatabaseViewModel.credentialStoreEntries(from: rootGroup),
                    for: reference.id
                )
            }
        } catch {
            return
        }
    }

    /// Cloud databases are primed from their cached copy: syncing is the
    /// app's job when the database itself is opened.
    private static func databaseData(for reference: DatabaseReference) async throws -> Data {
        if reference.isCloudBacked {
            guard let url = DatabaseListStore.cachedDatabaseURL(for: reference) else {
                throw CocoaError(.fileReadNoSuchFile)
            }
            return try await CoordinatedFileReader.performBlocking(timeout: .seconds(10)) {
                try CoordinatedFileReader.readData(from: url)
            }
        }
        return try await DatabaseViewModel.readLocalDatabase(reference: reference).data
    }
}
