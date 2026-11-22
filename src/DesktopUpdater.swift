import CryptoKit
import Foundation

enum DesktopUpdater {
    private static let repository = "d6vmc/ClaudeGuard-Desktop"
    private static let packageName = "ClaudeGuard-Desktop.pkg"
    private static let maximumPackageSize = 512 * 1024 * 1024

    struct Version: Comparable, CustomStringConvertible {
        private let components: [Int]

        init?(_ value: String) {
            let parts = value.split(separator: ".", omittingEmptySubsequences: false)
            guard parts.count == 3 else { return nil }
            let numbers = parts.compactMap { Int($0) }
            guard numbers.count == 3, numbers.allSatisfy({ $0 >= 0 }),
                  numbers.map(String.init).joined(separator: ".") == value else { return nil }
            components = numbers
        }

        var description: String { components.map(String.init).joined(separator: ".") }

        static func < (lhs: Self, rhs: Self) -> Bool {
            lhs.components.lexicographicallyPrecedes(rhs.components)
        }
    }

    struct Update: Equatable {
        let version: Version
        let url: URL
        let size: Int
        let sha256: String
    }

    struct Release: Decodable {
        let tag_name: String
        let draft: Bool
        let assets: [Asset]

        struct Asset: Decodable {
            let name: String
            let state: String
            let size: Int
            let digest: String?
            let browser_download_url: String
        }
    }

    enum Failure: Error {
        case unexpectedResponse
        case unverifiedRelease
        case unverifiedPackage
    }

    private final class Redirects: NSObject, URLSessionTaskDelegate {
        func urlSession(_ session: URLSession, task: URLSessionTask,
                        willPerformHTTPRedirection response: HTTPURLResponse, newRequest request: URLRequest,
                        completionHandler: @escaping (URLRequest?) -> Void) {
            completionHandler(request.url.map(DesktopUpdater.isOfficialURL) == true ? request : nil)
        }
    }

    static func isOfficialURL(_ url: URL) -> Bool {
        guard url.scheme == "https", url.user == nil, url.password == nil,
              url.port == nil || url.port == 443 else { return false }
        return ["api.github.com", "github.com", "release-assets.githubusercontent.com",
                "objects.githubusercontent.com"].contains(url.host)
    }

    private static func makeSession() -> URLSession {
        let config = URLSessionConfiguration.ephemeral
        config.httpShouldSetCookies = false
        config.timeoutIntervalForRequest = 25
        config.timeoutIntervalForResource = 15 * 60
        config.httpAdditionalHeaders = ["User-Agent": "ClaudeGuard-Desktop"]
        return URLSession(configuration: config, delegate: Redirects(), delegateQueue: nil)
    }

    static func findUpdate(after current: Version) async throws -> Update? {
        let session = makeSession()
        defer { session.finishTasksAndInvalidate() }
        var releases: [Release] = []
        for page in 1...10 {
            let url = URL(string: "https://api.github.com/repos/\(repository)/releases?per_page=100&page=\(page)")!
            var request = URLRequest(url: url, timeoutInterval: 20)
            request.setValue("application/vnd.github+json", forHTTPHeaderField: "Accept")
            let (data, response) = try await session.data(for: request)
            guard let http = response as? HTTPURLResponse, http.statusCode == 200,
                  http.url == url, data.count <= 4 * 1024 * 1024 else { throw Failure.unexpectedResponse }
            releases += try JSONDecoder().decode([Release].self, from: data)
            if http.value(forHTTPHeaderField: "Link")?.contains("rel=\"next\"") != true {
                return try newestUpdate(in: releases, after: current)
            }
        }
        throw Failure.unexpectedResponse
    }

    static func newestUpdate(in releases: [Release], after current: Version) throws -> Update? {
        let candidates = releases.compactMap { release -> (release: Release, version: Version, retry: Int)? in
            guard !release.draft, release.tag_name.hasPrefix("v"),
                  let suffix = release.tag_name.range(of: "-desktop"),
                  let version = Version(String(release.tag_name[release.tag_name.index(after: release.tag_name.startIndex)..<suffix.lowerBound])),
                  version > current else { return nil }
            let build = release.tag_name[suffix.upperBound...]
            if build.isEmpty { return (release, version, 0) }
            guard build.first == ".", let retry = Int(build.dropFirst()), retry > 0,
                  ".\(retry)" == build else { return nil }
            return (release, version, retry)
        }
        guard let candidate = candidates.max(by: { ($0.version, $0.retry) < ($1.version, $1.retry) }) else { return nil }
        let url = URL(string: "https://github.com/\(repository)/releases/download/\(candidate.release.tag_name)/\(packageName)")!
        guard let asset = candidate.release.assets.first(where: { $0.name == packageName }),
              asset.state == "uploaded", (1...maximumPackageSize).contains(asset.size),
              asset.browser_download_url == url.absoluteString,
              let digest = asset.digest, digest.hasPrefix("sha256:") else { throw Failure.unverifiedRelease }
        let sha256 = digest.dropFirst("sha256:".count)
        guard sha256.utf8.count == 64, sha256.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }) else {
            throw Failure.unverifiedRelease
        }
        return Update(version: candidate.version, url: url, size: asset.size, sha256: String(sha256))
    }

    static func download(_ update: Update, reusing cached: URL? = nil) async throws -> URL {
        if let cached, (try? verify(cached, for: update)) != nil { return cached }
        let session = makeSession()
        defer { session.finishTasksAndInvalidate() }
        let (file, response) = try await session.download(from: update.url)
        let manager = FileManager.default
        defer { try? manager.removeItem(at: file) }
        guard let http = response as? HTTPURLResponse, http.statusCode == 200,
              let origin = http.url, isOfficialURL(origin) else { throw Failure.unexpectedResponse }
        let directory = manager.temporaryDirectory.appendingPathComponent("ClaudeGuard-\(UUID())", isDirectory: true)
        try manager.createDirectory(at: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        let package = directory.appendingPathComponent(packageName)
        do {
            try manager.moveItem(at: file, to: package)
            try verify(package, for: update)
            return package
        } catch {
            try? manager.removeItem(at: directory)
            throw error
        }
    }

    static func verify(_ file: URL, for update: Update) throws {
        let handle = try FileHandle(forReadingFrom: file)
        defer { try? handle.close() }
        guard try handle.seekToEnd() == UInt64(update.size) else { throw Failure.unverifiedPackage }
        try handle.seek(toOffset: 0)
        var hash = SHA256()
        while let data = try handle.read(upToCount: 1024 * 1024), !data.isEmpty { hash.update(data: data) }
        guard hash.finalize().map({ String(format: "%02x", $0) }).joined() == update.sha256 else {
            throw Failure.unverifiedPackage
        }
    }
}
