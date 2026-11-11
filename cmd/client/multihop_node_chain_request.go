package main

import (
	"encoding/json"
	"errors"
	"io"
	"strings"

	"router-vpn/internal/common"
)

func (q multihopConnectRequest) ordered() bool { return q.nodesPresent || q.Nodes != nil }

func (q multihopConnectRequest) validateOrdered() error {
	if !q.ordered() {
		return nil
	}
	if q.Execution != "local" || q.EntryID != "" || q.ExitID != "" || q.Base != "" || q.EntryMode != "" || q.ExitMode != "" ||
		q.ExpectedSelectedNodeID == nil || *q.ExpectedSelectedNodeID == "" || q.ExpectedProfileTokens == nil {
		return errors.New("ordered Connect requires one explicit Local path and its complete original node revisions")
	}
	if err := common.ValidateMultihopNodes(q.Nodes); err != nil {
		return err
	}
	if q.Nodes[len(q.Nodes)-1].ID != *q.ExpectedSelectedNodeID {
		return errors.New("ordered Connect must end at its original selected node")
	}
	return nil
}

func (q *multihopConnectRequest) UnmarshalJSON(data []byte) error {
	fields, err := externalConnectJSONObject(data)
	if err != nil {
		return err
	}
	capture, err := decodeDesktopProfileExpectations(fields)
	if err != nil {
		return err
	}
	for name := range fields {
		if name != "nodes" && strings.EqualFold(name, "nodes") {
			return errors.New("ordered nodes must use their canonical JSON field")
		}
	}
	rawNodes, ordered := fields["nodes"]
	if ordered {
		for name := range fields {
			switch name {
			case "nodes", "execution", "expected_selected_node_id", "expected_profile_tokens":
			default:
				return errors.New("ordered Connect cannot mix another selection or an unknown field")
			}
		}
		var rows []json.RawMessage
		if json.Unmarshal(rawNodes, &rows) != nil || len(rows) < 2 || len(rows) > common.MultihopMaximumNodes {
			return errors.New("ordered Connect requires a bounded complete node array")
		}
		for _, raw := range rows {
			row, err := externalConnectJSONObject(raw)
			if err != nil || len(row) != 2 || row["id"] == nil || row["mode"] == nil {
				return errors.New("ordered node rows require only canonical identity and mode fields")
			}
		}
	}
	type wire multihopConnectRequest
	var decoded wire
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	decoded.desktopProfileExpectations, decoded.nodesPresent = capture, ordered
	result := multihopConnectRequest(decoded)
	if err := result.validateOrdered(); err != nil {
		return err
	}
	*q = result
	return nil
}

func decodeMultihopConnectRequest(body io.Reader) (multihopConnectRequest, error) {
	var q multihopConnectRequest
	data, err := io.ReadAll(body)
	if err == nil {
		err = json.Unmarshal(data, &q)
	}
	return q, err
}

// The caller holds a.mu inside the original connection operation. Validate
// public revisions before cloning private profiles or resolving their graph.
func (a *app) resolveNativeMultihopRequestLocked(q multihopConnectRequest) (multihopSelection, error) {
	if err := q.validateOrdered(); err != nil {
		return multihopSelection{}, err
	}
	var required []string
	if q.ordered() {
		for _, node := range q.Nodes {
			required = append(required, node.ID)
		}
	}
	if err := a.validateDesktopProfileExpectationsLocked(q.desktopProfileExpectations, required, q.ordered()); err != nil {
		return multihopSelection{}, err
	}
	store := cloneRouterProfileStore(a.profiles)
	control, ok := profileByID(store.Profiles, store.SelectedID)
	if !ok {
		return multihopSelection{}, errors.New("select a Router VPN control profile first")
	}
	if control.NodeKind == "external" {
		return multihopSelection{}, errors.New("selected node is external; use External Connect for its captured path")
	}
	selection, err := resolveNativeMultihopSelection(control, store.Profiles, q)
	if err == nil && q.present() && !q.ordered() {
		err = a.validateDesktopProfileExpectationsLocked(q.desktopProfileExpectations, []string{selection.Entry.ID, selection.Exit.ID}, false)
	}
	return selection, err
}

func (a *app) resolveLegacyMultihopRequestLocked(q multihopConnectRequest) (multihopSelection, error) {
	if q.ordered() {
		return multihopSelection{}, errors.New("ordered nodes require the protected native controller")
	}
	if err := a.validateDesktopProfileExpectationsLocked(q.desktopProfileExpectations, nil, false); err != nil {
		return multihopSelection{}, err
	}
	store := cloneRouterProfileStore(a.profiles)
	control, ok := profileByID(store.Profiles, store.SelectedID)
	if !ok {
		return multihopSelection{}, errors.New("select a Router VPN control profile first")
	}
	selection, err := resolveMultihopSelection(control, store.Profiles, q)
	if err == nil && q.present() {
		err = a.validateDesktopProfileExpectationsLocked(q.desktopProfileExpectations, []string{selection.Entry.ID, selection.Exit.ID}, false)
	}
	return selection, err
}
