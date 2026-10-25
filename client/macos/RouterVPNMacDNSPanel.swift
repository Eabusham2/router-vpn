import AppKit
import Foundation

final class RouterVPNMacDNSPanel: NSWindowController, NSWindowDelegate, NSTableViewDataSource, NSTableViewDelegate {
    let controller: RouterVPNMacDNSController
    let profileID: String
    private let heading = NSTextField(wrappingLabelWithString: "Reading the connected DNS path…")
    private let details = NSTextField(wrappingLabelWithString: "")
    private let owner = NSTextField(wrappingLabelWithString: "")
    private let draft = NSTextField(wrappingLabelWithString: "")
    private let table = NSTableView()
    private let spinner = NSProgressIndicator()
    private let transport = NSPopUpButton(frame: .zero, pullsDown: false)
    private let retestButton = NSButton(title: "Retest DNS", target: nil, action: nil)
    private let cancelButton = NSButton(title: "Cancel test", target: nil, action: nil)
    private let refreshButton = NSButton(title: "Refresh connection", target: nil, action: nil)
    private let fastestButton = NSButton(title: "Fastest measured", target: nil, action: nil)
    private let selectButton = NSButton(title: "Use selected row", target: nil, action: nil)
    private let saveButton = NSButton(title: "Save after Disconnect", target: nil, action: nil)
    private let closeButton = NSButton(title: "Close", target: nil, action: nil)
    private var state = RouterVPNMacDNSViewState()
    private var didClose = false
    private let onClosed: (RouterVPNMacDNSPanel) -> Void

    init(baseURL: URL, profileID: String, retest: Bool, onSaved: @escaping () -> Void,
         onClosed: @escaping (RouterVPNMacDNSPanel) -> Void) {
        self.profileID = profileID; self.onClosed = onClosed
        controller = RouterVPNMacDNSController(baseURL: baseURL, profileID: profileID)
        let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 1050, height: 660),
                              styleMask: [.titled, .closable, .resizable], backing: .buffered, defer: false)
        window.title = "Router VPN DNS measurements"; window.minSize = NSSize(width: 850, height: 570)
        window.isReleasedWhenClosed = false
        super.init(window: window)
        window.delegate = self; buildUI()
        controller.onChange = { [weak self] value in self?.apply(value) }
        controller.onSaved = onSaved
        controller.open(retest: retest)
    }
    required init?(coder: NSCoder) { nil }

    private func buildUI() {
        guard let content = window?.contentView else { return }
        let stack = NSStackView(); stack.orientation = .vertical; stack.alignment = .leading
        stack.spacing = 12; stack.edgeInsets = NSEdgeInsets(top: 20, left: 20, bottom: 20, right: 20)
        stack.translatesAutoresizingMaskIntoConstraints = false; content.addSubview(stack)
        NSLayoutConstraint.activate([stack.leadingAnchor.constraint(equalTo: content.leadingAnchor),
                                     stack.trailingAnchor.constraint(equalTo: content.trailingAnchor),
                                     stack.topAnchor.constraint(equalTo: content.topAnchor),
                                     stack.bottomAnchor.constraint(equalTo: content.bottomAnchor)])
        let title = NSTextField(labelWithString: "DNS response times"); title.font = .systemFont(ofSize: 26, weight: .bold)
        let explanation = NSTextField(wrappingLabelWithString: "Compare three real DNS queries per resolver over this connected path. The selected-policy row uses its actual route, including Home AdGuard through an entry. Public candidates use the exit. Values are DNS query medians, not ICMP ping or an ordinary-network lookup.")
        explanation.textColor = .secondaryLabelColor
        stack.addArrangedSubview(title); stack.addArrangedSubview(explanation)
        heading.font = .systemFont(ofSize: 14, weight: .semibold)
        heading.identifier = NSUserInterfaceItemIdentifier("dns-phase"); heading.setAccessibilityIdentifier("dns-phase")
        spinner.style = .spinning; spinner.controlSize = .small; spinner.isDisplayedWhenStopped = false
        let progress = NSStackView(views: [spinner, heading]); progress.orientation = .horizontal; progress.spacing = 8
        stack.addArrangedSubview(progress)
        owner.font = .systemFont(ofSize: 11); owner.textColor = .secondaryLabelColor
        details.identifier = NSUserInterfaceItemIdentifier("dns-measurement-status"); details.setAccessibilityIdentifier("dns-measurement-status")
        stack.addArrangedSubview(owner); stack.addArrangedSubview(details)
        let controls = NSStackView(); controls.orientation = .horizontal; controls.spacing = 8
        controls.addArrangedSubview(NSTextField(labelWithString: "Compare public resolvers over"))
        transport.addItems(withTitles: ["TCP", "DoT", "DoH"])
        transport.identifier = NSUserInterfaceItemIdentifier("dns-comparison-transport"); transport.setAccessibilityIdentifier("dns-comparison-transport")
        controls.addArrangedSubview(transport)
        for button in [retestButton, cancelButton, refreshButton] { controls.addArrangedSubview(button) }
        stack.addArrangedSubview(controls)

        table.dataSource = self; table.delegate = self; table.rowHeight = 27
        table.usesAlternatingRowBackgroundColors = true; table.allowsMultipleSelection = false
        table.identifier = NSUserInterfaceItemIdentifier("dns-results"); table.setAccessibilityIdentifier("dns-results")
        for (id, label, width) in [("name", "Resolver", 180.0), ("transport", "Transport", 75.0), ("address", "Address", 190.0),
                                    ("route", "Measured route", 150.0), ("median", "DNS median", 95.0), ("samples", "Samples", 70.0), ("result", "Result", 210.0)] {
            let column = NSTableColumn(identifier: NSUserInterfaceItemIdentifier(id)); column.title = label; column.width = width
            table.addTableColumn(column)
        }
        let scroll = NSScrollView(); scroll.documentView = table; scroll.hasVerticalScroller = true; scroll.hasHorizontalScroller = true
        scroll.autohidesScrollers = true; scroll.borderType = .bezelBorder
        stack.addArrangedSubview(scroll)
        scroll.widthAnchor.constraint(equalTo: stack.widthAnchor, constant: -40).isActive = true
        scroll.heightAnchor.constraint(greaterThanOrEqualToConstant: 180).isActive = true
        draft.identifier = NSUserInterfaceItemIdentifier("dns-measured-draft"); draft.setAccessibilityIdentifier("dns-measured-draft")
        stack.addArrangedSubview(draft)
        let actions = NSStackView(views: [fastestButton, selectButton, saveButton, closeButton]); actions.orientation = .horizontal; actions.spacing = 8
        stack.addArrangedSubview(actions)
        let note = NSTextField(wrappingLabelWithString: "Selecting a row only creates an expiring draft. Keep this window open, Disconnect in the main window, then Save. DNS details remain available for manual edits. Cancel or Close waits for the captured DNS workers to drain; neither changes the resolver automatically.")
        note.font = .systemFont(ofSize: 11); note.textColor = .secondaryLabelColor; stack.addArrangedSubview(note)
        let actionsByID: [(NSButton, String, Selector)] = [
            (retestButton, "dns-retest", #selector(retest)), (cancelButton, "dns-cancel", #selector(cancelTest)),
            (refreshButton, "dns-refresh", #selector(refreshConnection)), (fastestButton, "dns-fastest", #selector(fastest)),
            (selectButton, "dns-use-row", #selector(useSelected)), (saveButton, "dns-save", #selector(saveDraft)),
            (closeButton, "dns-close", #selector(closeRequested))]
        for (button, id, action) in actionsByID {
            button.bezelStyle = .rounded; button.target = self; button.action = action
            button.identifier = NSUserInterfaceItemIdentifier(id); button.setAccessibilityIdentifier(id)
        }
        for field in [explanation, owner, details, draft, note] {
            field.widthAnchor.constraint(equalTo: stack.widthAnchor, constant: -40).isActive = true
        }
    }

    private func apply(_ value: RouterVPNMacDNSViewState) {
        guard !didClose else { return }
        precondition(Thread.isMainThread)
        let previousID = table.selectedRow >= 0 && table.selectedRow < state.rows.count ? state.rows[table.selectedRow].id : nil
        state = value
        heading.stringValue = value.title; details.stringValue = value.detail; owner.stringValue = value.owner; draft.stringValue = value.draft
        table.reloadData()
        if let previousID, let index = state.rows.firstIndex(where: { $0.id == previousID }) { table.selectRowIndexes(IndexSet(integer: index), byExtendingSelection: false) }
        retestButton.isEnabled = value.canRetest; cancelButton.isEnabled = value.canCancel
        refreshButton.isEnabled = !value.busy; transport.isEnabled = !value.busy
        fastestButton.isEnabled = value.canSelect && value.rows.contains { $0.selectable }
        saveButton.isEnabled = value.canSave; updateRowSelection()
        closeButton.title = value.canCancel ? "Cancel and close" : "Close"
        if value.busy { spinner.startAnimation(nil) } else { spinner.stopAnimation(nil) }
        if value.closeReady { window?.performClose(nil) }
    }

    func numberOfRows(in tableView: NSTableView) -> Int { state.rows.count }
    func tableView(_ tableView: NSTableView, viewFor tableColumn: NSTableColumn?, row: Int) -> NSView? {
        guard row >= 0 && row < state.rows.count, let column = tableColumn else { return nil }
        let value = state.rows[row], text: String
        switch column.identifier.rawValue {
        case "name": text = value.name + (value.kind == "selected" ? " (selected policy)" : "")
        case "transport": text = ["tls": "DoT", "https": "DoH", "h3": "DoH3"][value.transport] ?? value.transport.uppercased()
        case "address": text = value.address.contains(":") ? "[\(value.address)]:\(value.port)" : "\(value.address):\(value.port)"
        case "route": text = value.route_label
        case "median": text = value.measurement
        case "samples": text = "\(value.samples)/\(value.samples + value.failed)"
        default: text = (value.failure ?? "").isEmpty ? (value.ready ? "Three successful queries" : "Waiting for queries") : value.failure!
        }
        let field = NSTextField(labelWithString: text); field.lineBreakMode = .byTruncatingTail; field.toolTip = text
        field.setAccessibilityLabel(column.title + ": " + text)
        if !value.ready && !(value.failure ?? "").isEmpty { field.textColor = .secondaryLabelColor }
        return field
    }
    func tableViewSelectionDidChange(_ notification: Notification) { updateRowSelection() }
    private func updateRowSelection() {
        selectButton.isEnabled = state.canSelect && table.selectedRow >= 0 && table.selectedRow < state.rows.count && state.rows[table.selectedRow].selectable
    }
    @objc func retest() { controller.retest(publicTransport: ["tcp", "tls", "https"][max(0, min(2, transport.indexOfSelectedItem))]) }
    @objc private func cancelTest() { controller.cancel() }
    @objc private func refreshConnection() { controller.open(publicTransport: ["tcp", "tls", "https"][max(0, min(2, transport.indexOfSelectedItem))]) }
    @objc private func fastest() { controller.choose("fastest") }
    @objc private func useSelected() {
        guard table.selectedRow >= 0, table.selectedRow < state.rows.count else { return }
        controller.choose(state.rows[table.selectedRow].id)
    }
    @objc private func saveDraft() { controller.save() }
    @objc private func closeRequested() { window?.performClose(nil) }
    func windowShouldClose(_ sender: NSWindow) -> Bool { controller.requestClose() }
    func windowWillClose(_ notification: Notification) {
        guard !didClose else { return }
        didClose = true; controller.stop(); onClosed(self)
    }
}

extension ProductWindowController {
    func showDNSMeasurement(profileID: String) {
        if let panel = dnsPanel {
            panel.window?.makeKeyAndOrderFront(nil)
            if panel.profileID == profileID { panel.retest() }
            else {
                panel.window?.performClose(nil)
                appendHelp("Close the previous captured DNS test before opening another node's Retest.")
            }
            return
        }
        let panel = RouterVPNMacDNSPanel(baseURL: routerVPNProductBaseURL, profileID: profileID, retest: true,
                                        onSaved: { [weak self] in self?.refreshProfiles() }) { [weak self] closed in
            guard let self, self.dnsPanel === closed else { return }
            self.dnsPanel = nil
        }
        dnsPanel = panel
        panel.showWindow(nil); panel.window?.center(); panel.window?.makeKeyAndOrderFront(nil)
    }
}
