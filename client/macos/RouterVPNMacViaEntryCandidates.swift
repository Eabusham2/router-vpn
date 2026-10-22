import AppKit
import Foundation

private final class RouterVPNMacViaEntryController: NSWindowController, NSWindowDelegate, NSTableViewDataSource, NSTableViewDelegate {
    private let api: ProductAPI
    private let entryID: String
    private let entryName: String
    private let candidates: [String]
    private let names: [String: String]
    private let contextCurrent: () -> Bool
    private let adopt: (String) -> Bool
    private let transaction = MacViaEntryCandidateSession()
    private let table = NSTableView()
    private let status = NSTextField(wrappingLabelWithString: "Preparing routed measurements…")
    private let retest = NSButton(title: "Retest", target: nil, action: nil)
    private let fastest = NSButton(title: "Choose Fastest", target: nil, action: nil)
    private let choose = NSButton(title: "Choose selected exit", target: nil, action: nil)
    private let closeButton = NSButton(title: "Cancel & close", target: nil, action: nil)
    private var clock: Timer?
    private var failureMessage = ""
    var retired: Bool { transaction.phase == .closed }

    init(api: ProductAPI, entryID: String, entryName: String, candidates: [String], names: [String: String],
         contextCurrent: @escaping () -> Bool, adopt: @escaping (String) -> Bool) {
        self.api = api; self.entryID = entryID; self.entryName = entryName; self.candidates = candidates; self.names = names
        self.contextCurrent = contextCurrent; self.adopt = adopt
        let panel = NSPanel(contentRect: NSRect(x: 0, y: 0, width: 780, height: 500), styleMask: [.titled, .closable, .resizable], backing: .buffered, defer: false)
        panel.title = "Exits via \(entryName)"; panel.minSize = NSSize(width: 680, height: 420); panel.isReleasedWhenClosed = false
        super.init(window: panel)
        panel.delegate = self
        buildUI()
    }
    required init?(coder: NSCoder) { nil }
    deinit { clock?.invalidate() }

    private func buildUI() {
        guard let content = window?.contentView else { return }
        let root = NSStackView(); root.orientation = .vertical; root.alignment = .leading; root.spacing = 12
        root.edgeInsets = NSEdgeInsets(top: 20, left: 20, bottom: 20, right: 20); root.translatesAutoresizingMaskIntoConstraints = false
        content.addSubview(root)
        NSLayoutConstraint.activate([root.leadingAnchor.constraint(equalTo: content.leadingAnchor), root.trailingAnchor.constraint(equalTo: content.trailingAnchor), root.topAnchor.constraint(equalTo: content.topAnchor), root.bottomAnchor.constraint(equalTo: content.bottomAnchor)])
        let heading = NSTextField(labelWithString: "Router VPN exits via \(entryName)")
        heading.font = .systemFont(ofSize: 22, weight: .semibold); root.addArrangedSubview(heading)
        let note = NSTextField(wrappingLabelWithString: "A temporary WireGuard path through this entry measures each saved Router VPN exit's TCP response. Five attempts per exit; only complete valid results can be chosen here. Selection changes the exit picker. Use Connect separately.")
        note.textColor = .secondaryLabelColor; root.addArrangedSubview(note)
        for (id, title, width) in [("node", "Exit", 180.0), ("route", "Measured path", 150.0), ("response", "TCP response", 230.0), ("samples", "Samples", 70.0)] {
            let column = NSTableColumn(identifier: NSUserInterfaceItemIdentifier(id)); column.title = title; column.width = width
            table.addTableColumn(column)
        }
        table.dataSource = self; table.delegate = self; table.allowsMultipleSelection = false; table.rowHeight = 30
        table.usesAlternatingRowBackgroundColors = true
        table.setAccessibilityLabel("Candidate exits measured through selected WireGuard entry")
        let scroll = NSScrollView(); scroll.documentView = table; scroll.hasVerticalScroller = true; scroll.autohidesScrollers = true
        root.addArrangedSubview(scroll)
        scroll.widthAnchor.constraint(equalTo: root.widthAnchor, constant: -40).isActive = true
        scroll.heightAnchor.constraint(greaterThanOrEqualToConstant: 210).isActive = true
        status.textColor = .secondaryLabelColor; root.addArrangedSubview(status)
        let buttons = NSStackView(); buttons.orientation = .horizontal; buttons.spacing = 8
        for button in [retest, fastest, choose, closeButton] { button.bezelStyle = .rounded; button.target = self; buttons.addArrangedSubview(button) }
        retest.action = #selector(retestCandidates); fastest.action = #selector(chooseFastest)
        choose.action = #selector(chooseSelected); closeButton.action = #selector(requestClose)
        root.addArrangedSubview(buttons)
        updateControls()
    }

    func start() {
        let timer = Timer(timeInterval: 1, repeats: true) { [weak self] _ in
            guard let self, !self.retired else { return }
            if !self.contextCurrent() {
                self.failureMessage = "The entry selection changed. Closing after the captured test is cleaned up."
                self.drain(.close); return
            }
            if let receipt = self.transaction.receipt, Date() >= receipt.expiresAt {
                self.status.stringValue = "Measurements expired. Retest through the selected entry before choosing an exit."
                self.table.reloadData()
            }
            self.updateControls()
        }
        clock = timer
        RunLoop.main.add(timer, forMode: .common)
        RunLoop.main.add(timer, forMode: .modalPanel)
        measure()
    }

    func numberOfRows(in tableView: NSTableView) -> Int { transaction.receipt?.rows.count ?? 0 }

    func tableView(_ tableView: NSTableView, objectValueFor tableColumn: NSTableColumn?, row: Int) -> Any? {
        guard let receipt = transaction.receipt, receipt.rows.indices.contains(row) else { return nil }
        let value = receipt.rows[row]
        switch tableColumn?.identifier.rawValue {
        case "node": return names[value.id] ?? value.id
        case "route": return "via \(entryName)"
        case "response":
            guard Date() < receipt.expiresAt else { return "Expired — Retest" }
            if let median = value.medianMS { return String(format: "%.2f ms", median) }
            return value.reason ?? "Unavailable"
        case "samples": return value.medianMS == nil ? "—" : "\(value.samples)"
        default: return nil
        }
    }

    func tableViewSelectionDidChange(_ notification: Notification) { updateControls() }

    private func selectedID() -> String? {
        guard let receipt = transaction.receipt, receipt.rows.indices.contains(table.selectedRow) else { return nil }
        return receipt.rows[table.selectedRow].id
    }

    private func updateControls() {
        let phase = transaction.phase
        retest.isEnabled = phase == .ready || phase == .idle
        let fastestID = transaction.receipt?.fastestID
        fastest.isEnabled = phase == .ready && fastestID.map { transaction.receipt?.eligible($0) == true } == true
        choose.isEnabled = phase == .ready && selectedID().map { transaction.receipt?.eligible($0) == true } == true
        table.isEnabled = phase == .ready
        closeButton.isEnabled = phase != .closed
        closeButton.title = phase == .cleanupFailed ? "Retry cleanup & close" : (phase == .measuring || phase == .validating || phase == .draining ? "Cancel & close" : "Close")
    }

    private func measure() {
        guard contextCurrent() else { failureMessage = "The selected entry changed. Reopen candidate measurements."; drain(.close); return }
        do {
            let captured = try transaction.begin(entryID: entryID, candidates: candidates)
            failureMessage = ""; status.stringValue = "Measuring TCP responses via \(entryName) over WireGuard…"
            table.reloadData(); updateControls()
            DispatchQueue.global(qos: .userInitiated).async { [self] in
                let result = Result { try api.request("/api/multihop/candidates", method: "POST", body: ["request_id": captured.requestID, "entry_id": captured.entryID, "base": "wg", "candidate_ids": captured.candidates, "samples": 5], timeout: 180) }
                DispatchQueue.main.async { [self] in
                    guard transaction.ticket == captured, transaction.phase == .measuring else { return }
                    do {
                        guard contextCurrent() else { throw MacViaEntryCandidateReceipt.issue("The selected entry changed during measurement.") }
                        guard try transaction.accept(result.get(), for: captured) else { return }
                        let count = transaction.receipt?.rows.filter { $0.medianMS != nil }.count ?? 0
                        status.stringValue = "\(count) measured exit(s) via \(entryName). Unavailable rows remain unmeasured. Results expire in two minutes."
                        table.reloadData(); updateControls()
                    } catch { failureMessage = error.localizedDescription; drain(.stay) }
                }
            }
        } catch { failureMessage = error.localizedDescription; status.stringValue = failureMessage; updateControls() }
    }

    @objc private func retestCandidates() { drain(.retest) }
    @objc private func chooseFastest() { if let id = transaction.receipt?.fastestID { validateAndChoose(id) } }
    @objc private func chooseSelected() { if let id = selectedID() { validateAndChoose(id) } }

    private func validateAndChoose(_ id: String) {
        do {
            guard contextCurrent() else { throw MacViaEntryCandidateReceipt.issue("The entry selection changed. Reopen candidate measurements.") }
            let captured = try transaction.beginValidation(exitID: id)
            status.stringValue = "Checking the exact source, network and measured exit before selection…"; updateControls()
            DispatchQueue.global(qos: .userInitiated).async { [self] in
                let result = Result { try api.request("/api/multihop/candidates/validate", method: "POST", body: ["request_id": captured.requestID, "entry_id": captured.entryID, "exit_id": id], timeout: 15) }
                DispatchQueue.main.async { [self] in
                    guard transaction.ticket == captured, transaction.phase == .validating else { return }
                    do {
                        guard contextCurrent() else { throw MacViaEntryCandidateReceipt.issue("The selected entry changed before adoption.") }
                        guard try transaction.acceptValidation(result.get(), for: captured, exitID: id) else { return }
                        guard adopt(id) else { throw MacViaEntryCandidateReceipt.issue("The exit is no longer in the saved node picker.") }
                        drain(.close)
                    } catch { failureMessage = error.localizedDescription; drain(.stay) }
                }
            }
        } catch { status.stringValue = error.localizedDescription; updateControls() }
    }

    @objc func requestClose() { drain(.close) }

    private func drain(_ action: MacViaEntryCandidateSession.AfterDrain) {
        if transaction.ticket == nil {
            if action == .close { finishClose() }
            else if action == .retest { measure() }
            return
        }
        guard let captured = transaction.beginDrain(action) else { return }
        status.stringValue = "Waiting for the captured candidate test to stop and clean up…"
        table.reloadData(); updateControls()
        DispatchQueue.global(qos: .userInitiated).async { [self] in
            let result = Result { try api.request("/api/multihop/candidates/cancel", method: "POST", body: ["request_id": captured.requestID], timeout: 180) }
            DispatchQueue.main.async { [self] in
                do {
                    guard let next = try transaction.acceptDrain(result.get(), for: captured) else { return }
                    switch next {
                    case .close: finishClose()
                    case .retest: measure()
                    case .stay:
                        status.stringValue = failureMessage.isEmpty ? "The test stopped. Retest to measure exits through this entry." : failureMessage + " Cleanup completed; Retest when ready."
                        updateControls()
                    }
                } catch {
                    transaction.failedDrain(captured)
                    status.stringValue = "Cleanup is not yet confirmed. Editing remains reserved. Retry cleanup & close. \(error.localizedDescription)"
                    updateControls()
                }
            }
        }
    }

    private func finishClose() {
        do {
            try transaction.closeIdle(); clock?.invalidate(); clock = nil
            NSApp.stopModal(); window?.orderOut(nil)
        } catch { status.stringValue = error.localizedDescription; updateControls() }
    }

    func windowShouldClose(_ sender: NSWindow) -> Bool {
        if retired { return true }
        requestClose(); return false
    }
}

extension ProductWindowController {
    /// NSPopUpButton invokes this only for a user selection; restoring saved
    /// settings with selectItem does not establish a temporary path.
    @objc func unifiedEntryCandidatesChanged() {
        refreshUnifiedHopOverlay()
        openViaEntryCandidates()
    }

    @objc func openViaEntryCandidates() {
        guard ensureMutationIdle("measuring candidate exits through the selected entry") else { return }
        let index = multihopEntryPopup.indexOfSelectedItem
        guard multihopNodeIDs.indices.contains(index) else { appendHelp("Choose a saved Router VPN entry before measuring exits."); return }
        let entryID = multihopNodeIDs[index]
        let routerIDs = Set(profiles.filter { ($0["node_kind"] as? String ?? "router-vpn").lowercased() == "router-vpn" }.compactMap { $0["id"] as? String })
        let candidates = multihopNodeIDs.filter { $0 != entryID && routerIDs.contains($0) }
        guard routerIDs.contains(entryID), !candidates.isEmpty, candidates.count <= 64 else {
            appendHelp("Candidate latency needs a saved Router VPN WireGuard entry and 1–64 distinct Router VPN exits. External nodes remain available through their supported connection controls."); return
        }
        var names: [String: String] = [:]
        for profile in profiles { if let id = profile["id"] as? String { names[id] = profile["name"] as? String ?? id } }
        let entryName = names[entryID] ?? entryID
        guard let lease = MacViaEntryCandidateReservation.shared.acquire() else { appendHelp("Another candidate transaction is still cleaning up."); return }
        defer { MacViaEntryCandidateReservation.shared.release(lease); refreshUnifiedChrome() }
        let stillCurrent = { [weak self] () -> Bool in
            guard let self else { return false }
            let selected = self.multihopEntryPopup.indexOfSelectedItem
            return self.multihopNodeIDs.indices.contains(selected) && self.multihopNodeIDs[selected] == entryID
        }
        let controller = RouterVPNMacViaEntryController(api: api, entryID: entryID, entryName: entryName, candidates: candidates, names: names, contextCurrent: stillCurrent) { [weak self] id in
            guard let self, stillCurrent(), let exitIndex = self.multihopNodeIDs.firstIndex(of: id), id != entryID else { return false }
            self.multihopExitPopup.selectItem(at: exitIndex)
            self.multihopComparisonLabel.stringValue = "Selected \(names[id] ?? id) from measured responses via \(entryName). Press Connect when ready."
            self.refreshUnifiedHopOverlay()
            return true
        }
        guard let panel = controller.window else { return }
        panel.center(); controller.showWindow(nil); panel.makeKeyAndOrderFront(nil)
        controller.start()
        repeat {
            _ = NSApp.runModal(for: panel)
            if !controller.retired { controller.requestClose() }
        } while !controller.retired
        controller.close()
    }
}
