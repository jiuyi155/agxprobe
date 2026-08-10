//
//  ContentView.swift
//  AGXProbe
//

import SwiftUI
import UIKit

struct ContentView: View {
    @StateObject private var model = VM()

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("AGXProbe — CVE-2026-64747 trigger test")
                .font(.headline)
            Text(model.status)
                .font(.caption)
                .foregroundColor(.secondary)

            HStack(spacing: 16) {
                Button(model.running ? "STOP" : "START") {
                    model.toggle()
                }
                .font(.title3.weight(.semibold))
                .padding(.horizontal, 28)
                .padding(.vertical, 10)
                .background(model.running ? Color.red : Color.green)
                .foregroundColor(.white)
                .cornerRadius(10)

                Button("Copy log") { model.copyLog() }
                    .font(.caption)
            }

            ScrollView {
                Text(model.log)
                    .font(.system(.footnote, design: .monospaced))
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .textSelection(.enabled)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .background(Color.black.opacity(0.85))
            .foregroundColor(.green)
            .cornerRadius(8)

            Text("If the device reboots (kernel panic) or the app dies mid-phase, open Settings → Privacy & Security → Analytics & Improvements → Analytics Data and look for a panic-full / ipa-log. Copy it off and share the tail.")
                .font(.caption2)
                .foregroundColor(.secondary)
        }
        .padding()
    }
}

@MainActor
final class VM: ObservableObject {
    @Published var running = false
    @Published var status = "idle — press START to drive AGX command queues"
    @Published var log = ""

    private let stress = AGXStress()
    private var timer: Timer?

    init() {
        guard stress != nil else {
            status = "FATAL: no MTLDevice — not running on real GPU / wrong device"
            return
        }
        status = "device ready"
    }

    func toggle() {
        if running {
            stress?.stop()
            running = false
            status = "stopped"
            timer?.invalidate(); timer = nil
        } else {
            stress?.start()
            running = true
            status = "RUNNING"
            timer = Timer.scheduledTimer(withTimeInterval: 0.5, repeats: true) { [weak self] _ in
                Task { @MainActor in
                    guard let self else { return }
                    self.log = self.stress?.currentLog ?? ""
                }
            }
        }
    }

    func copyLog() {
        UIPasteboard.general.string = stress?.currentLog
        status = "log copied to clipboard"
    }
}
