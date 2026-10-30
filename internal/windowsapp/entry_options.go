package windowsapp

import "errors"

func selfTestArgument(arguments []string) (bool, error) {
	if len(arguments) == 0 {
		return false, nil
	}
	if len(arguments) == 1 && arguments[0] == "--self-test" {
		return true, nil
	}
	return false, errors.New("Router VPN accepts only the optional --self-test argument")
}
