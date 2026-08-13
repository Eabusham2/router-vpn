#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WIN = ROOT / "client/RouterVPN-Windows-App.ps1"
MAC = ROOT / "client/macos/RouterVPNMacApp.swift"
LINUX = ROOT / "client/linux/routervpn-gtk.c"


def replace_once(text: str, old: str, new: str, label: str) -> str:
    n = text.count(old)
    if n != 1:
        raise SystemExit(f"{label}: expected exactly one anchor, found {n}: {old[:120]!r}")
    return text.replace(old, new, 1)


def migrate_windows() -> None:
    text = WIN.read_text(encoding="utf-8")
    if "Show-RouterVPNTutorial" in text and "TutorialButton" in text:
        print("Windows native onboarding already wired")
        return

    old_footer = '''    <TextBlock Grid.Row="2" Name="Footer" Margin="4,12,4,0" Foreground="#7E90B6" Text="Router VPN native Windows shell • controller bound to 127.0.0.1 only"/>
'''
    new_footer = '''    <Grid Grid.Row="2" Margin="4,12,4,0">
      <Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions>
      <TextBlock Name="Footer" Foreground="#7E90B6" VerticalAlignment="Center" Text="Router VPN native Windows shell • controller bound to 127.0.0.1 only"/>
      <Button Grid.Column="1" Name="TutorialButton" Content="Run Tutorial" Background="#33415F"/>
    </Grid>
'''
    text = replace_once(text, old_footer, new_footer, "Windows footer")
    text = replace_once(
        text,
        "'StateText','RouterCombo','ModeCombo','AutoButton','ConnectButton','DisconnectButton','NodesGrid','ModesGrid','PublicIpButton','EmergencyButton'",
        "'StateText','RouterCombo','ModeCombo','AutoButton','ConnectButton','DisconnectButton','NodesGrid','ModesGrid','PublicIpButton','EmergencyButton','TutorialButton'",
        "Windows self-test controls",
    )
    control_anchor = "$NodesGrid = Get-Control 'NodesGrid'; $ModesGrid = Get-Control 'ModesGrid'; $DiagnosticsBox = Get-Control 'DiagnosticsBox'\n"
    text = replace_once(text, control_anchor, control_anchor + "$TutorialButton = Get-Control 'TutorialButton'\n", "Windows control binding")

    onboarding = r'''
$RouterVPNOnboardingDir = Join-Path $PSScriptRoot '.routervpn-state'
$RouterVPNOnboardingFile = Join-Path $RouterVPNOnboardingDir 'windows-onboarding-v1.json'
$RouterVPNTutorialPages = @(
    @{ title='1. Install once; add routers as data'; body='Router VPN is installed once. Add Router is a private data operation: use secure home-LAN pairing/direct import when available, or import the small router-vpn-bundle.json file. Never treat linking as a reinstall.' },
    @{ title='2. Choose the router and mode'; body='Select the intended node first. Choose AUTO for the first proven working branch or an available manual logical mode. Tunnel base can be Auto, WireGuard, or AmneziaWG only when that mode reports the base ready; unavailable combinations stay unavailable.' },
    @{ title='3. DNS, LAN, MTU/Jumbo, and kill switch'; body='DNS is selected for the VPN path, not merely displayed. Home/fastest/custom/encrypted choices must match what the runtime can enforce. LAN Off must block ordinary home-LAN access while preserving only the minimum control path. MTU/Jumbo must have runtime effect. Strict kill-switch requests fail closed on unsupported lifecycle states.' },
    @{ title='4. Multihop and forwarding'; body='Multihop means entry node → different exit node → Internet and adds latency. Use it only when the selected pair/modes are compatible and the exit node passes private proof. Incoming forwarding has master plus per-rule state; TCP/UDP/both, ranges and targets must match the actual tunnel mode. Proxy-only modes cannot fake DNAT.' },
    @{ title='5. Connect, disconnect, and permissions'; body='Connect/AUTO may request the platform privileges required for a full-device VPN. Watch phase/progress instead of assuming success from a process starting. Disconnect is explicit; emergency stop is for failed transitions or recovery. Never disable Windows security globally to make Router VPN work.' },
    @{ title='6. Prove the path'; body='Connected is accepted only after the exact selected-router private identity/path proof succeeds. Public exit proof is separate: use Diagnostics → Prove public VPN exit. Retest DNS through the VPN path when DNS behavior is in question.' },
    @{ title='7. Troubleshoot and recover'; body='Use Methods to read availability/reasons, Diagnostics for path/DNS proof, 50-sample node latency when needed, and Emergency stop for rollback. If a mode is grey/unavailable, fix its stated prerequisite instead of forcing it. Setup Center Full Guide remains the complete home-node/setup reference.' },
    @{ title='8. Rerun any time'; body='This tutorial is separate from Setup Center onboarding. Finish marks only this Windows-app tutorial complete. The Run Tutorial button stays available permanently so you can restart from step 1 at any time.' }
)

function Get-RouterVPNOnboardingState {
    if (Test-Path -LiteralPath $RouterVPNOnboardingFile) {
        try {
            $state = Get-Content -LiteralPath $RouterVPNOnboardingFile -Raw | ConvertFrom-Json
            $step = [Math]::Max(0, [Math]::Min($RouterVPNTutorialPages.Count - 1, [int]$state.step))
            return @{ step=$step; completed=[bool]$state.completed }
        } catch { }
    }
    return @{ step=0; completed=$false }
}

function Save-RouterVPNOnboardingState([int]$Step, [bool]$Completed) {
    try {
        New-Item -ItemType Directory -Force -Path $RouterVPNOnboardingDir | Out-Null
        $tmp = "$RouterVPNOnboardingFile.tmp"
        @{ step=$Step; completed=$Completed; updated_at=(Get-Date).ToUniversalTime().ToString('o') } | ConvertTo-Json -Compress | Set-Content -LiteralPath $tmp -Encoding UTF8
        Move-Item -LiteralPath $tmp -Destination $RouterVPNOnboardingFile -Force
    } catch {
        # Never redirect Portable state into Registry/AppData merely because the
        # package location is not writable. The tutorial can still run; it will
        # simply reopen next launch until state can be saved beside the package.
    }
}

function Show-RouterVPNTutorial([switch]$Force) {
    $state = Get-RouterVPNOnboardingState
    if ($Force) { $state = @{ step=0; completed=$false }; Save-RouterVPNOnboardingState 0 $false }
    if ($state.completed -and -not $Force) { return }
    $step = [int]$state.step
    while ($true) {
        $page = $RouterVPNTutorialPages[$step]
        $last = ($step -eq $RouterVPNTutorialPages.Count - 1)
        $instructions = if ($last) { "`n`nYes = Finish • No = Back • Cancel = Close and resume later" } else { "`n`nYes = Next • No = Back • Cancel = Close and resume later" }
        $result = [System.Windows.MessageBox]::Show(
            [string]$page.body + $instructions,
            "Router VPN tutorial — " + [string]$page.title,
            [System.Windows.MessageBoxButton]::YesNoCancel,
            [System.Windows.MessageBoxImage]::Information
        )
        if ($result -eq [System.Windows.MessageBoxResult]::Cancel) { Save-RouterVPNOnboardingState $step $false; return }
        if ($result -eq [System.Windows.MessageBoxResult]::No) { if ($step -gt 0) { $step-- }; Save-RouterVPNOnboardingState $step $false; continue }
        if ($last) { Save-RouterVPNOnboardingState 0 $true; return }
        $step++
        Save-RouterVPNOnboardingState $step $false
    }
}

'''
    text = replace_once(text, "function Invoke-RouterVPN {\n", onboarding + "function Invoke-RouterVPN {\n", "Windows onboarding functions")
    text = replace_once(text, "(Get-Control 'RefreshButton').Add_Click({ Refresh-RouterVPN })\n", "(Get-Control 'RefreshButton').Add_Click({ Refresh-RouterVPN })\n$TutorialButton.Add_Click({ Show-RouterVPNTutorial -Force })\n", "Windows tutorial button")
    text = replace_once(text, "Refresh-RouterVPN\n$Timer.Start()\n[void]$Window.ShowDialog()", "Refresh-RouterVPN\n$Timer.Start()\n$Window.Add_ContentRendered({ Show-RouterVPNTutorial })\n[void]$Window.ShowDialog()", "Windows first-run hook")
    WIN.write_text(text, encoding="utf-8")
    print("Wired Windows native onboarding")


def migrate_macos() -> None:
    text = MAC.read_text(encoding="utf-8")
    if "showTutorial(force:" in text and "RouterVPNNativeOnboardingDoneV1" in text:
        print("macOS native onboarding already wired")
        return

    constants = '''private let routerVPNBaseURL = URL(string: "http://127.0.0.1:8788")!\nprivate let nativeAppContractVersion = 1\n'''
    replacement = constants + '''private let onboardingDoneKey = "RouterVPNNativeOnboardingDoneV1"\nprivate let onboardingStepKey = "RouterVPNNativeOnboardingStepV1"\n'''
    text = replace_once(text, constants, replacement, "macOS onboarding keys")

    init_anchor = '''        refreshTimer = Timer.scheduledTimer(withTimeInterval: 2, repeats: true) { [weak self] _ in
            self?.refreshStatus()
        }
'''
    init_replacement = init_anchor + '''        DispatchQueue.main.async { [weak self] in
            guard let self else { return }
            if !UserDefaults.standard.bool(forKey: onboardingDoneKey) { self.showTutorial(force: false) }
        }
'''
    text = replace_once(text, init_anchor, init_replacement, "macOS first-run hook")

    title_anchor = '''        titleRow.addArrangedSubview(title)
        titleRow.addArrangedSubview(NSView())
        titleRow.addArrangedSubview(statusLabel)
'''
    title_replacement = '''        titleRow.addArrangedSubview(title)
        titleRow.addArrangedSubview(NSView())
        titleRow.addArrangedSubview(makeButton("Run Tutorial", action: #selector(showTutorialAction)))
        titleRow.addArrangedSubview(statusLabel)
'''
    text = replace_once(text, title_anchor, title_replacement, "macOS tutorial button")

    method_anchor = '''    private func makeButton(_ title: String, action: Selector) -> NSButton {
'''
    methods = r'''    @objc private func showTutorialAction() { showTutorial(force: true) }

    private func showTutorial(force: Bool) {
        let pages: [(String, String)] = [
            ("1. Install once; add routers as data", "Router VPN is installed once. Add Router is private node data: use secure home-LAN pairing/direct import where offered, or import router-vpn-bundle.json. Linking a router is not an app reinstall."),
            ("2. Select node, mode, and base", "Choose the intended router first. AUTO tries proven candidates; manual mode uses only available logical modes. Tunnel base Auto/WireGuard/AmneziaWG is valid only where the runtime reports that base ready. Grey/unavailable combinations stay unavailable."),
            ("3. DNS, LAN, MTU/Jumbo, kill switch", "DNS must be enforced through the selected VPN path. LAN Off blocks ordinary home-LAN reachability while preserving the minimum control plane. MTU/Jumbo must change the runtime, not just UI state. Strict kill-switch semantics fail closed where a lifecycle cannot be proven."),
            ("4. Multihop and forwarding", "Real multihop is entry → different exit → Internet and adds latency; only compatible pairs may run and the exit needs private proof. Forwarding master/per-rule state, protocols, ranges and targets must match the actual dataplane; proxy-only modes cannot fake DNAT."),
            ("5. Permissions, connect, disconnect", "A full-device VPN may require platform/admin privileges from the local controller/runtime. Watch connection phase/progress. Disconnect is explicit and Emergency stop is the rollback path. For trusted local builds use the specific Privacy & Security → Open Anyway flow; never disable Gatekeeper globally."),
            ("6. Prove the selected path and exit", "Connected is not accepted until the exact selected-router private identity/path proof passes. Public VPN exit proof is a separate Diagnostics action. Retest DNS through the VPN when DNS behavior is in question."),
            ("7. Troubleshoot and support", "Use Methods for readiness reasons, Nodes for selection/latency, Diagnostics for exit/DNS proof, and Emergency stop for recovery. Setup Center Full Guide covers server deployment, secure pairing/import, forwarding and home-node administration."),
            ("8. Rerun any time", "This native macOS tutorial is separate from Setup Center onboarding. Finish marks only this app tutorial complete. Run Tutorial stays available permanently so you can restart from step 1.")
        ]
        if force {
            UserDefaults.standard.set(false, forKey: onboardingDoneKey)
            UserDefaults.standard.set(0, forKey: onboardingStepKey)
        } else if UserDefaults.standard.bool(forKey: onboardingDoneKey) { return }
        var step = max(0, min(pages.count - 1, UserDefaults.standard.integer(forKey: onboardingStepKey)))
        while true {
            let alert = NSAlert()
            alert.alertStyle = .informational
            alert.messageText = "Router VPN tutorial — \(pages[step].0)"
            alert.informativeText = pages[step].1
            alert.addButton(withTitle: step == pages.count - 1 ? "Finish" : "Next")
            alert.addButton(withTitle: step == 0 ? "Close & resume later" : "Back")
            alert.addButton(withTitle: "Close & resume later")
            let response = alert.runModal()
            if response == .alertFirstButtonReturn {
                if step == pages.count - 1 {
                    UserDefaults.standard.set(true, forKey: onboardingDoneKey)
                    UserDefaults.standard.set(0, forKey: onboardingStepKey)
                    return
                }
                step += 1
                UserDefaults.standard.set(step, forKey: onboardingStepKey)
                continue
            }
            if response == .alertSecondButtonReturn && step > 0 {
                step -= 1
                UserDefaults.standard.set(step, forKey: onboardingStepKey)
                continue
            }
            UserDefaults.standard.set(step, forKey: onboardingStepKey)
            return
        }
    }

'''
    text = replace_once(text, method_anchor, methods + method_anchor, "macOS onboarding methods")
    MAC.write_text(text, encoding="utf-8")
    print("Wired macOS native onboarding")


def migrate_linux() -> None:
    text = LINUX.read_text(encoding="utf-8")
    if "show_tutorial(App *app, gboolean force)" in text and "linux-onboarding-v1.ini" in text:
        print("Linux native onboarding already wired")
        return

    button_anchor = '''static GtkWidget *make_button(const char *label, GCallback callback, App *app) {
'''
    tutorial = r'''static const char *const tutorial_titles[] = {
    "1. Install once; add routers as data",
    "2. Select node, mode, and base",
    "3. DNS, LAN, MTU/Jumbo, kill switch",
    "4. Multihop and forwarding",
    "5. Permissions, connect, disconnect",
    "6. Prove the selected path and exit",
    "7. Troubleshoot and support",
    "8. Rerun any time"
};
static const char *const tutorial_bodies[] = {
    "Router VPN is installed once. Add Router is private node data: use secure home-LAN pairing/direct import where offered, or import router-vpn-bundle.json. Linking a router is not an app reinstall.",
    "Choose the intended router first. AUTO tries proven candidates; manual mode uses only available logical modes. Tunnel base Auto/WireGuard/AmneziaWG is valid only where the runtime reports that base ready. Grey/unavailable combinations stay unavailable.",
    "DNS must be enforced through the VPN path. LAN Off blocks ordinary home-LAN reachability while preserving only the minimum control plane. MTU/Jumbo must have runtime effect. Strict kill-switch semantics fail closed where a lifecycle cannot be proven.",
    "Real multihop is entry node → different exit node → Internet and adds latency. Only compatible pairs may run and the exit must pass private proof. Forwarding master/per-rule state, protocols, ranges and targets must match the actual dataplane; proxy-only modes cannot fake DNAT.",
    "A full-device VPN may require system/admin privileges. Watch connection phase/progress instead of assuming a process start means success. Disconnect is explicit and Emergency stop is the rollback path. Do not disable platform security globally.",
    "Connected is not accepted until the exact selected-router private identity/path proof passes. Public VPN exit proof is a separate Diagnostics action. Retest DNS through the VPN when DNS behavior is in question.",
    "Use Methods for readiness reasons, Nodes for selection/latency, Diagnostics for exit/DNS proof, and Emergency stop for recovery. Setup Center Full Guide covers server deployment, secure pairing/import, forwarding and home-node administration.",
    "This native Linux tutorial is separate from Setup Center onboarding. Finish marks only this app tutorial complete. Run Tutorial stays available permanently so you can restart from step 1."
};

typedef struct { GtkWidget *assistant; char *state_path; } TutorialState;

static char *tutorial_state_path(void) {
    char *dir = g_build_filename(g_get_user_config_dir(), "router-vpn", NULL);
    (void)g_mkdir_with_parents(dir, 0700);
    char *path = g_build_filename(dir, "linux-onboarding-v1.ini", NULL);
    g_free(dir);
    return path;
}

static void tutorial_load(const char *path, gboolean *done, gint *step) {
    *done = FALSE; *step = 0;
    GKeyFile *key = g_key_file_new();
    GError *error = NULL;
    if (g_key_file_load_from_file(key, path, G_KEY_FILE_NONE, &error)) {
        *done = g_key_file_get_boolean(key, "onboarding", "completed", NULL);
        *step = g_key_file_get_integer(key, "onboarding", "step", NULL);
        if (*step < 0 || *step >= (gint)G_N_ELEMENTS(tutorial_titles)) *step = 0;
    }
    if (error != NULL) g_error_free(error);
    g_key_file_unref(key);
}

static void tutorial_save(const char *path, gboolean done, gint step) {
    GKeyFile *key = g_key_file_new();
    g_key_file_set_boolean(key, "onboarding", "completed", done);
    g_key_file_set_integer(key, "onboarding", "step", step);
    g_key_file_set_string(key, "onboarding", "updated", "local-app-state");
    char *data = g_key_file_to_data(key, NULL, NULL);
    if (data != NULL) { (void)g_file_set_contents(path, data, -1, NULL); g_free(data); }
    g_key_file_unref(key);
}

static void tutorial_prepare(GtkAssistant *assistant, GtkWidget *page, gpointer data) {
    (void)page;
    TutorialState *state = data;
    tutorial_save(state->state_path, FALSE, gtk_assistant_get_current_page(assistant));
}

static void tutorial_cancel(GtkAssistant *assistant, gpointer data) {
    TutorialState *state = data;
    tutorial_save(state->state_path, FALSE, gtk_assistant_get_current_page(assistant));
    gtk_widget_destroy(GTK_WIDGET(assistant));
}

static void tutorial_apply(GtkAssistant *assistant, gpointer data) {
    TutorialState *state = data;
    tutorial_save(state->state_path, TRUE, 0);
    gtk_widget_destroy(GTK_WIDGET(assistant));
}

static void tutorial_destroy(GtkWidget *widget, gpointer data) {
    (void)widget;
    TutorialState *state = data;
    g_free(state->state_path);
    g_free(state);
}

static void show_tutorial(App *app, gboolean force) {
    gboolean done = FALSE; gint step = 0;
    char *path = tutorial_state_path();
    tutorial_load(path, &done, &step);
    if (force) { done = FALSE; step = 0; tutorial_save(path, FALSE, 0); }
    if (done && !force) { g_free(path); return; }

    GtkWidget *assistant = gtk_assistant_new();
    gtk_window_set_title(GTK_WINDOW(assistant), "Router VPN Tutorial");
    gtk_window_set_default_size(GTK_WINDOW(assistant), 700, 420);
    gtk_window_set_transient_for(GTK_WINDOW(assistant), GTK_WINDOW(app->window));
    gtk_window_set_modal(GTK_WINDOW(assistant), TRUE);
    for (guint i = 0; i < G_N_ELEMENTS(tutorial_titles); i++) {
        GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 14);
        gtk_container_set_border_width(GTK_CONTAINER(box), 24);
        GtkWidget *title = gtk_label_new(NULL);
        char *markup = g_markup_printf_escaped("<span size='x-large' weight='bold'>%s</span>", tutorial_titles[i]);
        gtk_label_set_markup(GTK_LABEL(title), markup); g_free(markup);
        gtk_widget_set_halign(title, GTK_ALIGN_START);
        GtkWidget *body = gtk_label_new(tutorial_bodies[i]);
        gtk_label_set_line_wrap(GTK_LABEL(body), TRUE);
        gtk_widget_set_halign(body, GTK_ALIGN_START);
        gtk_label_set_xalign(GTK_LABEL(body), 0.0f);
        gtk_box_pack_start(GTK_BOX(box), title, FALSE, FALSE, 0);
        gtk_box_pack_start(GTK_BOX(box), body, FALSE, FALSE, 0);
        gtk_widget_show_all(box);
        gint page = gtk_assistant_append_page(GTK_ASSISTANT(assistant), box);
        gtk_assistant_set_page_title(GTK_ASSISTANT(assistant), box, tutorial_titles[i]);
        gtk_assistant_set_page_complete(GTK_ASSISTANT(assistant), box, TRUE);
        gtk_assistant_set_page_type(GTK_ASSISTANT(assistant), box, i == G_N_ELEMENTS(tutorial_titles)-1 ? GTK_ASSISTANT_PAGE_CONFIRM : (page == 0 ? GTK_ASSISTANT_PAGE_INTRO : GTK_ASSISTANT_PAGE_CONTENT));
    }
    TutorialState *state = g_new0(TutorialState, 1);
    state->assistant = assistant; state->state_path = path;
    g_signal_connect(assistant, "prepare", G_CALLBACK(tutorial_prepare), state);
    g_signal_connect(assistant, "cancel", G_CALLBACK(tutorial_cancel), state);
    g_signal_connect(assistant, "close", G_CALLBACK(tutorial_apply), state);
    g_signal_connect(assistant, "apply", G_CALLBACK(tutorial_apply), state);
    g_signal_connect(assistant, "destroy", G_CALLBACK(tutorial_destroy), state);
    gtk_assistant_set_current_page(GTK_ASSISTANT(assistant), step);
    gtk_widget_show_all(assistant);
}

static void on_tutorial(GtkButton *button, gpointer data) {
    (void)button;
    show_tutorial((App *)data, TRUE);
}

'''
    text = replace_once(text, button_anchor, tutorial + button_anchor, "Linux tutorial implementation")
    header_anchor = '''    app->status = gtk_label_new("Checking…");
    gtk_box_pack_end(GTK_BOX(header), app->status, FALSE, FALSE, 0);
'''
    header_replacement = '''    app->status = gtk_label_new("Checking…");
    gtk_box_pack_end(GTK_BOX(header), app->status, FALSE, FALSE, 0);
    gtk_box_pack_end(GTK_BOX(header), make_button("Run Tutorial", G_CALLBACK(on_tutorial), app), FALSE, FALSE, 0);
'''
    text = replace_once(text, header_anchor, header_replacement, "Linux tutorial button")
    first_run_anchor = '''    gtk_widget_show_all(app.window);
    gtk_main();
'''
    text = replace_once(text, first_run_anchor, '''    gtk_widget_show_all(app.window);
    show_tutorial(&app, FALSE);
    gtk_main();
''', "Linux first-run hook")
    LINUX.write_text(text, encoding="utf-8")
    print("Wired Linux native onboarding")


migrate_windows()
migrate_macos()
migrate_linux()
