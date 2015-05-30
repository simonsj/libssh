#define LIBSSH_STATIC

#include "torture.h"
#include <libssh/libssh.h>
#include "libssh/priv.h"

static void setup(void **state) {
    ssh_session session = ssh_new();

    *state = session;
}

static void teardown(void **state) {
    ssh_free(*state);
}

static void torture_options_set_proxycommand(void **state) {
    ssh_session session = *state;
    char command[200];
    int rc;

    rc = ssh_options_set(session, SSH_OPTIONS_HOST, torture_libssh_host());
    assert_true(rc == 0);

    snprintf(command, sizeof(command), "nc %s %s", torture_libssh_host(), torture_libssh_port());
    rc = ssh_options_set(session, SSH_OPTIONS_PROXYCOMMAND, command);
    assert_true(rc == 0);
    rc = ssh_connect(session);
    assert_true(rc == SSH_OK);
}

static void torture_options_set_proxycommand_notexist(void **state) {
    ssh_session session = *state;
    int rc;

    rc = ssh_options_set(session, SSH_OPTIONS_HOST, torture_libssh_host());
    assert_true(rc == 0);

    rc = ssh_options_set(session, SSH_OPTIONS_PROXYCOMMAND, "this_command_does_not_exist");
    assert_true(rc == SSH_OK);
    rc = ssh_connect(session);
    assert_true(rc == SSH_ERROR);
}

int torture_run_tests(void) {
    int rc;
    UnitTest tests[] = {
        unit_test_setup_teardown(torture_options_set_proxycommand, setup, teardown),
        unit_test_setup_teardown(torture_options_set_proxycommand_notexist, setup, teardown),
    };


    ssh_init();

    torture_filter_tests(tests);
    rc = run_tests(tests);
    ssh_finalize();

    return rc;
}
