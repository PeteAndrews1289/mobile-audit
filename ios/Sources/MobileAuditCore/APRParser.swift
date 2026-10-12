import CoreFoundation
import CryptoKit
import Foundation

public enum APRParser {
    private static let maxBytes = 256 * 1024 * 1024
    private static let maxLineBytes = 1024 * 1024
    private static let maxRecords = 1_000_000

    private struct Counts {
        var network = 0
        var access = 0
    }

    private struct AccessEvent {
        let line: Int
        let date: Date
        let category: String
        let kind: String
        let intervalID: String
    }

    public static func index(_ url: URL) throws -> APRIndex {
        var counts: [String: Counts] = [:]
        let hash = try stream(url) { _, record in
            if record["type"] as? String == "networkActivity",
               let bundleID = validBundleID(record["bundleID"]) {
                var value = counts[bundleID] ?? Counts()
                value.network += 1
                counts[bundleID] = value
            } else if record["type"] as? String == "access",
                      let bundleID = accessBundleID(record) {
                var value = counts[bundleID] ?? Counts()
                value.access += 1
                counts[bundleID] = value
            }
        }
        let apps = counts.map { bundleID, value in
            APRAppOverview(bundleID: bundleID, networkEntries: value.network, accessEvents: value.access)
        }.sorted { $0.bundleID.localizedStandardCompare($1.bundleID) == .orderedAscending }
        return APRIndex(artifactSHA256: hash, apps: apps)
    }

    public static func snapshot(_ url: URL, bundleID: String) throws -> APRSnapshot {
        let fractional = ISO8601DateFormatter()
        fractional.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        let basic = ISO8601DateFormatter()
        basic.formatOptions = [.withInternetDateTime]
        func date(_ value: Any?) -> Date? {
            guard let text = value as? String, text.count <= 64 else { return nil }
            return fractional.date(from: text) ?? basic.date(from: text)
        }

        var network: [NetworkContact] = []
        var access: [AccessEvent] = []
        var skipped = 0
        let hash = try stream(url) { line, record in
            switch record["type"] as? String {
            case "networkActivity" where record["bundleID"] as? String == bundleID:
                guard let domain = record["domain"] as? String,
                      !domain.isEmpty, domain.count <= 253,
                      let first = date(record["firstTimeStamp"]),
                      let last = date(record["timeStamp"]), first <= last,
                      let hits = integer(record["hits"]), hits >= 0 else {
                    skipped += 1
                    return
                }
                network.append(NetworkContact(
                    sourceLine: line,
                    domain: domain,
                    firstSeenAt: first,
                    lastSeenAt: last,
                    reportedContacts: hits,
                    initiatedType: (record["initiatedType"] as? String).map { String($0.prefix(100)) },
                    domainType: integer(record["domainType"]),
                    domainOwner: (record["domainOwner"] as? String).map { String($0.prefix(253)) }
                ))
            case "access" where accessBundleID(record) == bundleID:
                guard let stamp = date(record["timeStamp"]),
                      let category = record["category"] as? String, !category.isEmpty,
                      let kind = record["kind"] as? String,
                      kind == "intervalBegin" || kind == "intervalEnd" else {
                    skipped += 1
                    return
                }
                let intervalID = (record["identifier"] as? String) ?? "line-\(line)"
                access.append(AccessEvent(
                    line: line, date: stamp, category: String(category.prefix(100)),
                    kind: kind, intervalID: intervalID
                ))
            default:
                break
            }
        }
        guard !network.isEmpty || !access.isEmpty else { throw APRImportError.noEntries(bundleID) }
        network.sort { ($0.lastSeenAt, $0.domain, $0.sourceLine) < ($1.lastSeenAt, $1.domain, $1.sourceLine) }
        return APRSnapshot(
            bundleID: bundleID,
            artifactSHA256: hash,
            networkContacts: network,
            resourceAccesses: pair(access),
            skippedSelectedRecords: skipped
        )
    }

    private static func validBundleID(_ value: Any?) -> String? {
        guard let text = value as? String, !text.isEmpty, text.count <= 255 else { return nil }
        return text
    }

    private static func accessBundleID(_ record: [String: Any]) -> String? {
        guard let accessor = record["accessor"] as? [String: Any],
              accessor["identifierType"] as? String == "bundleID" else { return nil }
        return validBundleID(accessor["identifier"])
    }

    private static func integer(_ value: Any?) -> Int? {
        guard let number = value as? NSNumber,
              CFGetTypeID(number as CFTypeRef) != CFBooleanGetTypeID() else { return nil }
        let result = number.intValue
        guard number.doubleValue == Double(result) else { return nil }
        return result
    }

    private static func pair(_ events: [AccessEvent]) -> [ResourceAccess] {
        var grouped: [String: [AccessEvent]] = [:]
        for event in events { grouped[event.intervalID, default: []].append(event) }
        var result: [ResourceAccess] = []
        for group in grouped.values {
            let ordered = group.sorted {
                if $0.date != $1.date { return $0.date < $1.date }
                if $0.kind != $1.kind { return $0.kind == "intervalBegin" }
                return $0.line < $1.line
            }
            var opened: AccessEvent?
            for event in ordered {
                if event.kind == "intervalBegin" {
                    if let previous = opened {
                        result.append(ResourceAccess(category: previous.category, startedAt: previous.date,
                                                     endedAt: nil, sourceLines: [previous.line]))
                    }
                    opened = event
                } else if let previous = opened, previous.date <= event.date,
                          previous.category == event.category {
                    result.append(ResourceAccess(category: previous.category, startedAt: previous.date,
                                                 endedAt: event.date, sourceLines: [previous.line, event.line]))
                    opened = nil
                } else {
                    result.append(ResourceAccess(category: event.category, startedAt: nil,
                                                 endedAt: event.date, sourceLines: [event.line]))
                }
            }
            if let previous = opened {
                result.append(ResourceAccess(category: previous.category, startedAt: previous.date,
                                             endedAt: nil, sourceLines: [previous.line]))
            }
        }
        return result.sorted {
            if $0.observedAt != $1.observedAt { return $0.observedAt < $1.observedAt }
            return $0.sourceLines.lexicographicallyPrecedes($1.sourceLines)
        }
    }

    private static func stream(_ url: URL, visit: (Int, [String: Any]) throws -> Void) throws -> String {
        let handle: FileHandle
        do { handle = try FileHandle(forReadingFrom: url) }
        catch { throw APRImportError.unreadableFile }
        defer { try? handle.close() }

        var hash = SHA256()
        var buffer = Data()
        var totalBytes = 0
        var lineNumber = 0

        func process(_ raw: Data) throws {
            lineNumber += 1
            if lineNumber > maxRecords { throw APRImportError.tooManyRecords }
            if raw.count > maxLineBytes { throw APRImportError.lineTooLarge(lineNumber) }
            if raw.allSatisfy({ $0 == 0x20 || $0 == 0x09 || $0 == 0x0D }) { return }
            do {
                guard let record = try JSONSerialization.jsonObject(with: raw) as? [String: Any] else {
                    throw APRImportError.invalidJSON(lineNumber)
                }
                try visit(lineNumber, record)
            } catch is APRImportError {
                throw APRImportError.invalidJSON(lineNumber)
            } catch {
                throw APRImportError.invalidJSON(lineNumber)
            }
        }

        while true {
            let chunk: Data
            do { chunk = try handle.read(upToCount: 64 * 1024) ?? Data() }
            catch { throw APRImportError.unreadableFile }
            if chunk.isEmpty { break }
            totalBytes += chunk.count
            if totalBytes > maxBytes { throw APRImportError.fileTooLarge }
            hash.update(data: chunk)
            buffer.append(chunk)
            while let newline = buffer.firstIndex(of: 0x0A) {
                let line = Data(buffer[..<newline])
                buffer.removeSubrange(buffer.startIndex...newline)
                try process(line)
            }
            if buffer.count > maxLineBytes { throw APRImportError.lineTooLarge(lineNumber + 1) }
        }
        if !buffer.isEmpty { try process(buffer) }
        return hash.finalize().map { String(format: "%02x", $0) }.joined()
    }
}
