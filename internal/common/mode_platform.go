package common

import (
	"encoding/json"
	"runtime"
)

// UnmarshalJSON keeps the shared modes.json portable while allowing macOS to
// select the platform-safe SMART/CUSTOM wrapper at load time. Linux/Windows get
// the byte-for-byte catalog semantics. Normal modes are already explicitly
// routed through run-platform.sh in the shared catalog.
func (m *Mode) UnmarshalJSON(data []byte) error {
	type modeAlias Mode
	var raw modeAlias
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	*m = Mode(raw)
	applyModePlatformCompatibility(m, runtime.GOOS)
	return nil
}

func applyModePlatformCompatibility(m *Mode, platform string) {
	if m == nil || platform != "darwin" {
		return
	}
	if len(m.Command) >= 2 && m.Command[0] == "python3" && m.Command[1] == "./orchestrate.py" {
		m.Command = append([]string(nil), m.Command...)
		m.Command[1] = "./orchestrate-platform.py"
	}
	if len(m.StopCommand) == 1 && m.StopCommand[0] == "./stop-mode.sh" {
		m.StopCommand = []string{"./stop-mode-platform.sh"}
	}
}
