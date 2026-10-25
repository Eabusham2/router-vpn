import AppKit
import Foundation

final class RouterVPNMacMTUPanel: NSWindowController, NSWindowDelegate {
    let controller: RouterVPNMacMTUController
    private let heading = NSTextField(wrappingLabelWithString: "Reading current MTU status…")
    private let details = NSTextField(wrappingLabelWithString: "")
    private let owner = NSTextField(wrappingLabelWithString: "")
    private let candidates = NSTextView()
    private let spinner = NSProgressIndicator()
    private let retestButton = NSButton(title: "Retest MTU", target: nil, action: nil)
    private let cancelButton = NSButton(title: "Cancel test", target: nil, action: nil)
    private let refreshButton = NSButton(title: "Observe current Auto MTU", target: nil, action: nil)
    private let closeButton = NSButton(title: "Close", target: nil, action: nil)
    private var didClose = false
    private let onClosed: (RouterVPNMacMTUPanel) -> Void

    init(baseURL: URL, retest: Bool, onClosed: @escaping (RouterVPNMacMTUPanel) -> Void) {
        controller = RouterVPNMacMTUController(baseURL: baseURL)
        self.onClosed = onClosed
        let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 790, height: 660),
                              styleMask: [.titled, .closable, .resizable], backing: .buffered, defer: false)
        window.title = "Router VPN MTU"
        window.minSize = NSSize(width: 680, height: 530)
        super.init(window: window)
        window.delegate = self
        buildUI()
        controller.onChange = { [weak self] state in self?.apply(state) }
        controller.open(retest: retest)
    }
    required init?(coder: NSCoder) { nil }

    private func buildUI() {
        guard let content = window?.contentView else { return }
        let stack = NSStackView(); stack.orientation = .vertical; stack.alignment = .leading
        stack.spacing = 12; stack.edgeInsets = NSEdgeInsets(top: 22, left: 22, bottom: 22, right: 22)
        stack.translatesAutoresizingMaskIntoConstraints = false
        content.addSubview(stack)
        NSLayoutConstraint.activate([stack.leadingAnchor.constraint(equalTo: content.leadingAnchor),
                                     stack.trailingAnchor.constraint(equalTo: content.trailingAnchor),
                                     stack.topAnchor.constraint(equalTo: content.topAnchor),
                                     stack.bottomAnchor.constraint(equalTo: content.bottomAnchor)])
        let title = NSTextField(labelWithString: "Connection MTU"); title.font = .systemFont(ofSize: 28, weight: .bold)
        let explanation = NSTextField(wrappingLabelWithString: "Follow Auto MTU or retest this connected path. Measurements and rollback belong to the captured connection. Saved values remain labelled as unmeasured until a fresh test reports them.")
        explanation.textColor = .secondaryLabelColor
        stack.addArrangedSubview(title); stack.addArrangedSubview(explanation)
        heading.font = .systemFont(ofSize: 15, weight: .semibold)
        heading.setAccessibilityIdentifier("mtu-phase")
        heading.identifier = NSUserInterfaceItemIdentifier("mtu-phase")
        spinner.style = .spinning; spinner.controlSize = .small; spinner.isDisplayedWhenStopped = false
        let progress = NSStackView(views: [spinner, heading]); progress.orientation = .horizontal; progress.spacing = 8
        stack.addArrangedSubview(progress)
        progress.widthAnchor.constraint(equalTo: stack.widthAnchor, constant: -44).isActive = true
        heading.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
        details.setAccessibilityIdentifier("mtu-measurement-status")
        details.identifier = NSUserInterfaceItemIdentifier("mtu-measurement-status")
        owner.font = .monospacedSystemFont(ofSize: 10, weight: .regular); owner.textColor = .secondaryLabelColor
        owner.setAccessibilityIdentifier("mtu-captured-owner")
        owner.identifier = NSUserInterfaceItemIdentifier("mtu-captured-owner")
        stack.addArrangedSubview(details); stack.addArrangedSubview(owner)
        let label = NSTextField(labelWithString: "Reported candidates"); label.font = .systemFont(ofSize: 12, weight: .semibold)
        stack.addArrangedSubview(label)
        candidates.isEditable = false; candidates.isSelectable = true
        candidates.isVerticallyResizable = true; candidates.isHorizontallyResizable = false
        candidates.autoresizingMask = [.width]; candidates.textContainer?.widthTracksTextView = true
        candidates.font = .monospacedSystemFont(ofSize: 12, weight: .regular)
        candidates.textContainerInset = NSSize(width: 10, height: 10)
        candidates.setAccessibilityIdentifier("mtu-candidates")
        candidates.identifier = NSUserInterfaceItemIdentifier("mtu-candidates")
        let scroll = NSScrollView(); scroll.hasVerticalScroller = true; scroll.autohidesScrollers = true
        scroll.borderType = .bezelBorder; scroll.documentView = candidates
        stack.addArrangedSubview(scroll)
        scroll.widthAnchor.constraint(equalTo: stack.widthAnchor, constant: -44).isActive = true
        scroll.heightAnchor.constraint(greaterThanOrEqualToConstant: 170).isActive = true
        let actions = NSStackView(); actions.orientation = .horizontal; actions.spacing = 8
        for button in [retestButton, cancelButton, refreshButton, closeButton] {
            button.bezelStyle = .rounded; button.target = self; actions.addArrangedSubview(button)
        }
        retestButton.action = #selector(retest); retestButton.setAccessibilityIdentifier("mtu-retest")
        cancelButton.action = #selector(cancel); cancelButton.setAccessibilityIdentifier("mtu-cancel")
        refreshButton.action = #selector(observe); refreshButton.setAccessibilityIdentifier("mtu-observe")
        closeButton.action = #selector(closeRequested); closeButton.setAccessibilityIdentifier("mtu-close")
        for (button, identifier) in [(retestButton, "mtu-retest"), (cancelButton, "mtu-cancel"), (refreshButton, "mtu-observe"), (closeButton, "mtu-close")] {
            button.identifier = NSUserInterfaceItemIdentifier(identifier)
        }
        stack.addArrangedSubview(actions)
        let note = NSTextField(wrappingLabelWithString: "Cancel stays pending until the captured test finishes rolling back. Closing an Auto observer leaves Auto running; closing a manual test requests cancellation and waits for it to drain.")
        note.font = .systemFont(ofSize: 11); note.textColor = .secondaryLabelColor
        stack.addArrangedSubview(note)
        for field in [explanation, details, owner, note] {
            field.widthAnchor.constraint(equalTo: stack.widthAnchor, constant: -44).isActive = true
        }
    }

    private func apply(_ state: RouterVPNMacMTUViewState) {
        guard !didClose else { return }
        precondition(Thread.isMainThread)
        heading.stringValue = state.title; details.stringValue = state.detail; owner.stringValue = state.owner
        candidates.string = state.measurements
        retestButton.isEnabled = state.canRetest; cancelButton.isEnabled = state.canCancel
        refreshButton.isEnabled = !state.busy
        closeButton.title = controller.manual && state.busy ? "Cancel and close" : "Close"
        if state.busy { spinner.startAnimation(nil) } else { spinner.stopAnimation(nil) }
        if state.closeReady { window?.performClose(nil) }
    }

    @objc func retest() { controller.retest() }
    @objc private func cancel() { controller.cancel() }
    @objc private func observe() { controller.open() }
    @objc private func closeRequested() { window?.performClose(nil) }

    func windowShouldClose(_ sender: NSWindow) -> Bool { controller.requestClose() }
    func windowWillClose(_ notification: Notification) {
        guard !didClose else { return }
        didClose = true; controller.stop(); onClosed(self)
    }
}

extension ProductWindowController {
    func showMTUPanel(retest: Bool) {
        if let panel = mtuPanel, panel.window?.isVisible == true {
            panel.window?.makeKeyAndOrderFront(nil)
            if retest { panel.retest() }
            return
        }
        let panel = RouterVPNMacMTUPanel(baseURL: routerVPNProductBaseURL, retest: retest) { [weak self] closed in
            guard let self, self.mtuPanel === closed else { return }
            self.mtuPanel = nil
        }
        mtuPanel = panel
        panel.showWindow(nil); panel.window?.center(); panel.window?.makeKeyAndOrderFront(nil)
    }

    @objc func observeMTU() { showMTUPanel(retest: false) }
}
