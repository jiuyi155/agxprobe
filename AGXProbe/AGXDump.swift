//
//  AGXDump.swift
//  AGXProbe
//
//  Dump the userland AGX / Metal / IOKit binaries out of this process's own
//  address space.  The dyld shared cache is mapped (readable) into every
//  process, so a plain sideloaded app can copy the AGXG14P / Metal / IOKit
//  images out — no jailbreak, no Mac.  We need these to RE the userland side
//  of CVE-2026-64747: which IOConnectCallMethod feeds [queue+0x170]/[0x700]
//  (the command-count bitmask the kernel slot-fill reads unchecked).
//
//  Output: <Documents>/agx_dump/<img>.bin — one file per matched image, bytes
//  laid out as a rebased memory image (header at offset 0, each segment's
//  payload at (vmaddr - imageMinVM)), plus <img>.txt with the meta (segment
//  list, symtab offsets).  Retrievable via Files app (UIFileSharingEnabled)
//  or i4Tools / 3uTools app-sandbox browser.
//

import Foundation
import MachO
import Darwin

// dyld image enumeration — declare directly to avoid depending on the `dyld`
// Swift module being present in the SDK (bulletproof against CI SDK changes).
@_silgen_name("_dyld_image_count")
private func _dyld_image_count() -> UInt32
@_silgen_name("_dyld_get_image_header")
private func _dyld_get_image_header(_ imageIndex: UInt32) -> UnsafePointer<mach_header>?
@_silgen_name("_dyld_get_image_name")
private func _dyld_get_image_name(_ imageIndex: UInt32) -> UnsafePointer<CChar>?
@_silgen_name("_dyld_get_image_vmaddr_slide")
private func _dyld_get_image_vmaddr_slide(_ imageIndex: UInt32) -> Int

enum AGXDump {

    /// Substring of the image path that we keep. Matches the device GPU
    /// driver (AGXG14P), the Metal framework, the CoreMTL impl, IOKit and the
    /// IOGPU/AGXMetal userclients.
    static let wanted: [String] = [
        "AGX",       // AGXG14P.bundle / AGXShared / AGXMetal
        "Metal",     // Metal.framework
        "CoreMTL",
        "IOKit",
        "IOGPU",
    ]

    static let maxSpan = 300 * 1024 * 1024  // safety cap on any single image

    static func run() -> String {
        var out: [String] = []
        guard let dir = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first else {
            return "FATAL: no Documents dir"
        }
        let dumpDir = dir.appendingPathComponent("agx_dump", isDirectory: true)
        try? FileManager.default.createDirectory(at: dumpDir, withIntermediateDirectories: true)

        let count = _dyld_image_count()
        out.append("dyld images: \(count)")

        var dumped = 0
        for idx in 0..<count {
            guard let namePtr = _dyld_get_image_name(idx) else { continue }
            let name = String(cString: namePtr)
            guard wanted.contains(where: { name.contains($0) }) else { continue }

            guard let header = _dyld_get_image_header(idx) else {
                out.append("  skip \(name): no header"); continue
            }
            let slide = _dyld_get_image_vmaddr_slide(idx)
            let h64 = header.withMemoryRebound(to: mach_header_64.self, capacity: 1) { $0 }
            guard h64.pointee.magic == MH_MAGIC_64 else {
                out.append("  skip \(name): not 64-bit"); continue
            }

            let base = UnsafeRawPointer(h64)
            let ncmds = Int(h64.pointee.ncmds)
            let sizeofcmds = Int(h64.pointee.sizeofcmds)
            let lcStart = base.advanced(by: MemoryLayout<mach_header_64>.size)

            var segs: [(name: String, vm: UInt64, vs: UInt64)] = []
            var minVM = UInt64.max
            var maxEnd: UInt64 = 0
            var off = 0
            var symtab: symtab_command? = nil
            var dysymtab: dysymtab_command? = nil

            while off < sizeofcmds {
                let lc = lcStart.advanced(by: off).assumingMemoryBound(to: load_command.self)
                let cmd = lc.pointee.cmd
                let cmdsz = Int(lc.pointee.cmdsize)
                if cmdsz <= 0 { break }
                if cmd == UInt32(LC_SEGMENT_64) {
                    let seg = lcStart.advanced(by: off).assumingMemoryBound(to: segment_command_64.self)
                    let vm = seg.pointee.vmaddr
                    let vs = seg.pointee.vmsize
                    if vs > 0 {
                        minVM = min(minVM, vm)
                        maxEnd = max(maxEnd, vm &+ vs)
                        let sn = withUnsafeBytes(of: seg.pointee.segname) { p -> String in
                            let c = p.baseAddress!.assumingMemoryBound(to: CChar.self)
                            return String(cString: c)
                        }
                        segs.append((sn, vm, vs))
                    }
                } else if cmd == UInt32(LC_SYMTAB) {
                    symtab = lcStart.advanced(by: off).assumingMemoryBound(to: symtab_command.self).pointee
                } else if cmd == UInt32(LC_DYSYMTAB) {
                    dysymtab = lcStart.advanced(by: off).assumingMemoryBound(to: dysymtab_command.self).pointee
                }
                off += cmdsz
            }

            guard minVM != UInt64.max, maxEnd > minVM else {
                out.append("  skip \(name): no segments"); continue
            }
            let span = maxEnd - minVM
            guard span <= maxSpan else {
                out.append("  skip \(name): span \(span) > cap"); continue
            }

            // Build a rebased memory image: byte at (vm - minVM).
            var buf = [UInt8](repeating: 0, count: Int(span))
            buf.withUnsafeMutableBytes { rb in
                let dst = rb.baseAddress!
                for s in segs {
                    let o = Int(s.vm - minVM)
                    let n = Int(s.vs)
                    guard o + n <= Int(span), n > 0 else { continue }
                    memcpy(dst.advanced(by: o), base.advanced(by: o), n)
                }
            }

            // Sanity: header magic at offset 0 must survive the copy.
            guard buf.count >= 4 else { out.append("  FAIL \(name): too small"); continue }
            let magicCheck = UInt32(buf[0]) | (UInt32(buf[1]) << 8) | (UInt32(buf[2]) << 16) | (UInt32(buf[3]) << 24)
            if magicCheck != MH_MAGIC_64 {
                out.append("  WARN \(name): header magic mismatch after copy")
            }

            let safeName = name.components(separatedBy: "/").last ?? "img\(idx)"
            let binURL = dumpDir.appendingPathComponent("\(safeName).bin")
            let metaURL = dumpDir.appendingPathComponent("\(safeName).txt")
            do {
                try Data(buf).write(to: binURL)
                var lines = [String]()
                lines.append("image: \(name)")
                lines.append("slide: \(slide)")
                lines.append("minVM: \(String(format: "%llx", minVM))  span: \(String(format: "%llx", span)) (\(span / 1024) KB)")
                for s in segs {
                    lines.append(String(format: "  %-16@ vm=%llx  sz=%llx", s.name, s.vm, s.vs))
                }
                if let st = symtab {
                    lines.append(String(format: "symtab: symoff=%u nsyms=%u stroff=%u strsize=%u", st.symoff, st.nsyms, st.stroff, st.strsize))
                }
                if let ds = dysymtab {
                    lines.append(String(format: "dysymtab: ilocalsym=%u nlocalsym=%u iextdefsym=%u nextdefsym=%u", ds.ilocalsym, ds.nlocalsym, ds.iextdefsym, ds.nextdefsym))
                }
                try lines.joined(separator: "\n").write(to: metaURL, atomically: true, encoding: .utf8)
                dumped += 1
                out.append("DUMPED \(safeName).bin  \(span / 1024) KB  (\(segs.count) segs)")
            } catch {
                out.append("  FAIL write \(safeName): \(error)")
            }
        }

        out.append("=== dumped \(dumped) images → \(dumpDir.path)")
        return out.joined(separator: "\n")
    }
}
