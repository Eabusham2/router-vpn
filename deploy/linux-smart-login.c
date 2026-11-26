// Run the qualification user on openvt's foreground terminal under the stock login PAM service.
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <security/pam_appl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static int diagnostics = -1;

static void report(const char *stage, int pam_code, int error) {
    // Numeric codes and fixed stage names only: never PAM messages or credentials.
    dprintf(diagnostics, "stage=%s pam_code=%d errno=%d\n", stage, pam_code, error);
}

static int converse(int n, const struct pam_message **messages, struct pam_response **out, void *data) {
    struct pam_response *responses = calloc(n, sizeof(*responses));
    if (!responses) return PAM_BUF_ERR;
    for (int i = 0; i < n; ++i) {
        if (messages[i]->msg_style == PAM_PROMPT_ECHO_OFF) {
            responses[i].resp = strdup(data);
            if (!responses[i].resp) goto failed;
        } else if (messages[i]->msg_style != PAM_TEXT_INFO && messages[i]->msg_style != PAM_ERROR_MSG) {
            goto failed;
        }
    }
    *out = responses;
    return PAM_SUCCESS;
failed:
    for (int i = 0; i < n; ++i) free(responses[i].resp);
    free(responses);
    return PAM_CONV_ERR;
}

int main(int argc, char **argv) {
    if (argc != 7) return 1;
    diagnostics = open(argv[5], O_WRONLY | O_APPEND | O_NOFOLLOW | O_CLOEXEC);
    struct stat info;
    if (diagnostics < 0 || fstat(diagnostics, &info) || !S_ISREG(info.st_mode) ||
        info.st_uid != 0 || (info.st_mode & 0777) != 0600 || info.st_nlink != 1) {
        fputs("The qualification login diagnostic file is unavailable or not private root-owned storage.\n", stderr);
        return 1;
    }
    if (getuid() != 0 || geteuid() != 0) { report("root-preflight", 0, EPERM); return 1; }
    if (!isatty(STDIN_FILENO)) { report("tty-preflight", 0, errno); return 1; }
    char *tty = ttyname(STDIN_FILENO);
    if (!tty) { report("tty-name", 0, errno); return 1; }
    errno = 0;
    struct passwd *user = getpwnam(argv[1]);
    if (!user || !user->pw_uid) { report("user-lookup", 0, errno); return 1; }
    uid_t uid = user->pw_uid;
    gid_t gid = user->pw_gid;
    char *home = strdup(user->pw_dir);
    if (!home) { report("home-copy", 0, errno); return 1; }
    FILE *file = fopen(argv[2], "re");
    char password[128] = {0};
    if (!file) { report("password-open", 0, errno); free(home); return 1; }
    if (!fgets(password, sizeof(password), file)) {
        report("password-read", 0, errno);
        fclose(file); free(home); return 1;
    }
    fclose(file);
    password[strcspn(password, "\n")] = 0;
    struct pam_conv conv = {converse, password};
    pam_handle_t *pam = NULL;
    int result = 1, code = PAM_SUCCESS, credentials = 0, session = 0;
#define PAM_STAGE(label, call) do { \
    code = (call); report((label), code, 0); \
    if (code != PAM_SUCCESS) goto done; \
} while (0)
    PAM_STAGE("pam-start", pam_start("login", argv[1], &conv, &pam));
    PAM_STAGE("pam-tty", pam_set_item(pam, PAM_TTY, tty));
    PAM_STAGE("pam-authenticate", pam_authenticate(pam, 0));
    PAM_STAGE("pam-account", pam_acct_mgmt(pam, 0));
    PAM_STAGE("pam-establish-credentials", pam_setcred(pam, PAM_ESTABLISH_CRED));
    credentials = 1;
    PAM_STAGE("pam-open-session", pam_open_session(pam, 0));
    session = 1;
#undef PAM_STAGE
    explicit_bzero(password, sizeof(password));
    pid_t child = fork();
    if (child == 0) {
        char **env = pam_getenvlist(pam);
        for (char **p = env; p && *p; ++p) putenv(*p);
#define CHILD_STAGE(label, call) do { \
    if ((call) != 0) { report((label), 0, errno); _exit(1); } \
} while (0)
        CHILD_STAGE("set-home", setenv("HOME", home, 1));
        CHILD_STAGE("set-user", setenv("USER", argv[1], 1));
        CHILD_STAGE("set-logname", setenv("LOGNAME", argv[1], 1));
        CHILD_STAGE("initgroups", initgroups(argv[1], gid));
        CHILD_STAGE("setgid", setgid(gid));
        CHILD_STAGE("setuid", setuid(uid));
#undef CHILD_STAGE
        if (getuid() != uid || geteuid() != uid) { report("uid-readback", 0, EPERM); _exit(1); }
        report("session-python-exec", 0, 0);
        execl("/usr/bin/python3", "python3", "-I", argv[3], argv[4], NULL);
        report("session-python-exec-failed", 0, errno);
        _exit(1);
    }
    if (child < 0) {
        report("session-fork", 0, errno);
    } else {
        int status = 0;
        if (waitpid(child, &status, 0) != child) {
            report("session-wait", 0, errno);
        } else {
            dprintf(diagnostics, "stage=session-child exit_code=%d signal=%d\n",
                    WIFEXITED(status) ? WEXITSTATUS(status) : -1,
                    WIFSIGNALED(status) ? WTERMSIG(status) : 0);
            result = WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : 1;
        }
    }
done:
    explicit_bzero(password, sizeof(password));
    if (session) {
        int cleanup = pam_close_session(pam, 0);
        report("pam-close-session", cleanup, 0);
        if (cleanup != PAM_SUCCESS) result = 1;
    }
    if (credentials) {
        int cleanup = pam_setcred(pam, PAM_DELETE_CRED);
        report("pam-delete-credentials", cleanup, 0);
        if (cleanup != PAM_SUCCESS) result = 1;
    }
    if (pam) {
        int cleanup = pam_end(pam, code);
        report("pam-end", cleanup, 0);
        if (cleanup != PAM_SUCCESS) result = 1;
    }
    if (result == 0) {
        // Only this root parent can publish retirement after its child and every
        // PAM cleanup stage succeeded. No openvt status convention is trusted.
        int receipt = open(argv[6], O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
        if (receipt < 0) {
            report("retirement-receipt-open", 0, errno);
            result = 1;
        } else {
            const char marker[] = "routervpn-smart-login-retired-v1\n";
            ssize_t written = write(receipt, marker, sizeof(marker) - 1);
            int error = written == (ssize_t)(sizeof(marker) - 1) ? 0 : errno ? errno : EIO;
            if (close(receipt) != 0 && error == 0) error = errno;
            if (error != 0) {
                unlink(argv[6]);
                report("retirement-receipt-write", 0, error);
                result = 1;
            }
        }
    }
    free(home);
    close(diagnostics);
    return result;
}
