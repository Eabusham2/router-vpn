package main

func nativeDarwinMultihopCommand(a *app, sel multihopSelection) (*desktopNodeLaunch, error) {
	return prepareOwnedNativeMultihopCommand(a, sel, nil)
}
