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
        // Stack layout measures alignment rectangles, which omit a native
        // button's outer frame. Contain those frames in each row so the
        // document's spacing also separates the complete clickable controls.
        func containButtonFrames(_ row: NSStackView) {
            var padding = row.edgeInsets
            var leadingFrameInset: CGFloat = 0
            var trailingFrameInset: CGFloat = 0
            for view in row.arrangedSubviews {
                let insets = view.alignmentRectInsets
                padding.top = max(padding.top, max(0, insets.top))
                padding.left = max(padding.left, max(0, insets.left))
                padding.bottom = max(padding.bottom, max(0, insets.bottom))
                padding.right = max(padding.right, max(0, insets.right))
                leadingFrameInset = max(leadingFrameInset, max(0, insets.left))
                trailingFrameInset = max(trailingFrameInset, max(0, insets.right))
            }
            row.edgeInsets = padding
            // Spacing is also measured between alignment rectangles. Reserve
            // both outer insets even when a hidden neighbor rejoins the row.
            if row.orientation == .horizontal {
                row.spacing += leadingFrameInset + trailingFrameInset
            }
            row.setContentCompressionResistancePriority(.required, for: .vertical)
        }
        let profileRow = NSStackView(views: [profiles])
        profileRow.orientation = .horizontal
        profileRow.alignment = .centerY
        profileRow.translatesAutoresizingMaskIntoConstraints = false
        containButtonFrames(profileRow)
        containButtonFrames(primaryRow)
        controls.insertArrangedSubview(profileRow, at: position)
        objc_setAssociatedObject(self, &connectionProfileChromeInstalledKey, true, .OBJC_ASSOCIATION_RETAIN_NONATOMIC)
    }
}

// macOS daily Profiles control: full setup-aware CRUD; exact current node/mode/CUSTOM/multihop graph; no auto-connect and no copied node secrets.
