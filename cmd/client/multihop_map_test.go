package main

import (
	"fmt"
	"reflect"
	"testing"
	"time"

	"router-vpn/internal/common"
)

func TestMapFollowsCompleteExtendedOriginalGraph(t *testing.T) {
	for _, count := range []int{9, 16, 96} {
		nodes := make([]desktopNodeChainMember, count)
		ids := make([]string, count)
		for i := range nodes {
			ids[i] = fmt.Sprintf("original-%d", i)
			nodes[i].Profile.ID = ids[i]
		}
		graph := activeMultihopGraph{EntryID: ids[0], ExitID: ids[count-1], ChainNodes: count, Started: time.Now().UTC()}
		graph.captureMapNodes(nodes)
		nodes[count-2].Profile.ID = "later-saved-edit"
		status := map[string]any{"connected": true}
		graph.addMapRoute(status)
		if !reflect.DeepEqual(status["active_node_ids"], ids) {
			t.Fatal("map truncated the proved original graph", count)
		}
		changed := graph
		changed.orderedIDs[count-2] = "another-original"
		if changed.mapRouteID() == graph.mapRouteID() {
			t.Fatal("late route mutation reused its map identity", count)
		}
	}
}

func TestMapFollowsPublishedOrderedGraph(t *testing.T) {
	nodes := []desktopNodeChainMember{}
	for _, id := range []string{"entry", "relay", "exit"} {
		nodes = append(nodes, desktopNodeChainMember{Profile: common.RouterProfile{ID: id}})
	}
	graph := activeMultihopGraph{EntryID: "entry", ExitID: "exit", ChainNodes: 3, Started: time.Now().UTC()}
	graph.captureMapNodes(nodes)
	nodes[1].Profile.ID = "later edit"
	status := map[string]any{"connected": true}
	graph.addMapRoute(status)
	if !reflect.DeepEqual(status["active_node_ids"], []string{"entry", "relay", "exit"}) || status["active_route_id"] != graph.mapRouteID() {
		t.Fatal("map lost the original published route")
	}
	changed := graph
	changed.orderedIDs[1] = "other relay"
	if changed.mapRouteID() == graph.mapRouteID() {
		t.Fatal("different intermediate node reused the visible route identity")
	}
	next := graph
	next.Started = graph.Started.Add(time.Millisecond)
	if next.mapRouteID() == graph.mapRouteID() {
		t.Fatal("reconnected graph inherited the prior path measurement")
	}
	graph.orderedIDs[1] = ""
	status = map[string]any{"connected": true}
	graph.addMapRoute(status)
	if _, present := status["active_node_ids"]; present {
		t.Fatal("incomplete graph became a visible shortcut")
	}
	graph.ChainNodes = 0
	if !reflect.DeepEqual(graph.mapNodeIDs(), []string{"entry", "exit"}) {
		t.Fatal("two-node graph lost its active endpoints")
	}
	status = map[string]any{"connected": false}
	graph.addMapRoute(status)
	if _, present := status["active_route_id"]; present {
		t.Fatal("disconnected graph remained visible as active")
	}
}
