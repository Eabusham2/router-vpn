import AppKit

func installRouterVPNMainMenu(_ app: NSApplication) {
    let main = NSMenu(title: "MainMenu")
    let appItem = NSMenuItem()
    main.addItem(appItem)

    let appMenu = NSMenu(title: "Router VPN")
    let about = NSMenuItem(
        title: "About Router VPN",
        action: #selector(NSApplication.orderFrontStandardAboutPanel(_:)),
        keyEquivalent: ""
    )
    about.target = app
    appMenu.addItem(about)
    appMenu.addItem(.separator())

    let quit = NSMenuItem(
        title: "Quit Router VPN",
        action: #selector(NSApplication.terminate(_:)),
        keyEquivalent: "q"
    )
    quit.target = app
    appMenu.addItem(quit)
    appItem.submenu = appMenu
    app.mainMenu = main
}
