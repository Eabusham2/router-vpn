import AppKit
import ObjectiveC

private var connectionProfileChromeInstalledKey: UInt8 = 0

extension ProductWindowController {
    func installUnifiedConnectionProfileChrome() {
        if (objc_getAssociatedObject(self, &connectionProfileChromeInstalledKey) as? Bool) == true { return }
        guard let content = window?.contentView else { return }
        func find(_ view: NSView, id: String) -> NSView? {
            if view.identifier?.rawValue == id { return view }
            for child in view.subviews { if let hit = find(child, id: id) { return hit } }
            return nil
        }
        func arrangedStack(containing child: NSView, in view: NSView) -> NSStackView? {
            if let stack = view as? NSStackView, stack.arrangedSubviews.contains(where: { $0 === child }) { return stack }
            for nested in view.subviews { if let hit = arrangedStack(containing: child, in: nested) { return hit } }
            return nil
        }
        guard let kill = find(content, id: "unified-kill-switch"),
              let primaryRow = arrangedStack(containing: kill, in: content),
              let controls = arrangedStack(containing: primaryRow, in: content),
              controls.orientation == .vertical,
              let position = controls.arrangedSubviews.firstIndex(where: { $0 === primaryRow }) else { return }
        let profiles = NSButton(title: "Profiles", target: self, action: #selector(manageConnectionProfiles))
        profiles.identifier = NSUserInterfaceItemIdentifier("unified-connection-profiles")
        profiles.bezelStyle = .rounded
        profiles.controlSize = .small
        profiles.toolTip = "Add / Load / Update / Delete complete non-secret connection setups including the exact visible multihop graph. Loading never auto-connects."
        profiles.translatesAutoresizingMaskIntoConstraints = false
        // Participate in the scroll document's measured layout. A floating
        // sheet overlay covered Kill switch at both compact and normal sizes.
        controls.insertArrangedSubview(profiles, at: position)
        objc_setAssociatedObject(self, &connectionProfileChromeInstalledKey, true, .OBJC_ASSOCIATION_RETAIN_NONATOMIC)
    }
}

// macOS daily Profiles control: full setup-aware CRUD; exact current node/mode/CUSTOM/multihop graph; no auto-connect and no copied node secrets.
