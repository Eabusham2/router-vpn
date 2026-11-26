// Run the qualification user on openvt's foreground terminal under the stock login PAM service.
#include <grp.h>
#include <pwd.h>
#include <security/pam_appl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

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
    if (argc != 5 || getuid() != 0 || !isatty(STDIN_FILENO)) return 1;
    struct passwd *user = getpwnam(argv[1]);
    if (!user || !user->pw_uid) return 1;
    uid_t uid = user->pw_uid;
    gid_t gid = user->pw_gid;
    char *home = strdup(user->pw_dir);
    if (!home) return 1;
    FILE *file = fopen(argv[2], "re");
    char password[128] = {0};
    if (!file || !fgets(password, sizeof(password), file)) return 1;
    fclose(file);
    password[strcspn(password, "\n")] = 0;
    struct pam_conv conv = {converse, password};
    pam_handle_t *pam = NULL;
    if (pam_start("login", argv[1], &conv, &pam) != PAM_SUCCESS ||
        pam_set_item(pam, PAM_TTY, ttyname(STDIN_FILENO)) != PAM_SUCCESS ||
        pam_authenticate(pam, 0) != PAM_SUCCESS || pam_acct_mgmt(pam, 0) != PAM_SUCCESS ||
        pam_setcred(pam, PAM_ESTABLISH_CRED) != PAM_SUCCESS || pam_open_session(pam, 0) != PAM_SUCCESS) {
        fputs("The stock PAM login service could not open the qualification terminal session.\n", stderr);
        return 1;
    }
    explicit_bzero(password, sizeof(password));
    pid_t child = fork();
    if (child == 0) {
        char **env = pam_getenvlist(pam);
        for (char **p = env; p && *p; ++p) putenv(*p);
        if (setenv("HOME", home, 1) || setenv("USER", argv[1], 1) ||
            setenv("LOGNAME", argv[1], 1) || initgroups(argv[1], gid) ||
            setgid(gid) || setuid(uid) || getuid() != uid || geteuid() != uid) _exit(1);
        execl("/usr/bin/python3", "python3", "-I", argv[3], argv[4], NULL);
        _exit(1);
    }
    int status = 1;
    int ok = child > 0 && waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0;
    pam_close_session(pam, 0);
    pam_setcred(pam, PAM_DELETE_CRED);
    pam_end(pam, PAM_SUCCESS);
    return ok ? 0 : 1;
}
