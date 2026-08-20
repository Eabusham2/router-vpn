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
        guard let sheet = find(content, id: "unified-sheet") else { return }
        objc_setAssociatedObject(self, &connectionProfileChromeInstalledKey, true, .OBJC_ASSOCIATION_RETAIN_NONATOMIC)
        let profiles = NSButton(title: "Profiles", target: self, action: #selector(manageConnectionProfiles))
        profiles.identifier = NSUserInterfaceItemIdentifier("unified-connection-profiles")
        profiles.bezelStyle = .rounded
        profiles.controlSize = .small
        profiles.toolTip = "Add / Load / Update / Delete complete non-secret connection setups including the exact visible multihop graph. Loading never auto-connects."
        profiles.translatesAutoresizingMaskIntoConstraints = false
        sheet.addSubview(profiles)
        NSLayoutConstraint.activate([
            profiles.leadingAnchor.constraint(equalTo: sheet.leadingAnchor, constant: 18),
            profiles.topAnchor.constraint(equalTo: sheet.topAnchor, constant: 10),
        ])
    }
}

// macOS daily Profiles control: full setup-aware CRUD; exact current node/mode/CUSTOM/multihop graph; no auto-connect and no copied node secrets.
