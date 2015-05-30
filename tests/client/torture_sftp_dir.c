#define LIBSSH_STATIC

#include "torture.h"
#include "sftp.c"

static void setup(void **state) {
    ssh_session session;
    struct torture_sftp *t;

    session = torture_ssh_session(torture_libssh_host(), torture_libssh_port(),
            torture_libssh_user(), torture_libssh_password());

    assert_non_null(session);
    t = torture_sftp_session(session);
    assert_false(t == NULL);

    *state = t;
}

static void teardown(void **state) {
    struct torture_sftp *t = *state;

    assert_false(t == NULL);

    torture_rmdirs(t->testdir);
    torture_sftp_close(t);
}

static void torture_sftp_mkdir(void **state) {
    struct torture_sftp *t = *state;
    char tmpdir[128] = {0};
    int rc;

    assert_false(t == NULL);

    snprintf(tmpdir, sizeof(tmpdir) - 1, "%s/mkdir_test", t->testdir);

    rc = sftp_mkdir(t->sftp, tmpdir, 0755);
    if(rc != SSH_OK)
        fprintf(stderr,"error:%s\n",ssh_get_error(t->sftp->session));
    assert_true(rc == 0);

    /* check if it really has been created */
    assert_true(torture_isdir(tmpdir));

    rc = sftp_rmdir(t->sftp, tmpdir);
    assert_true(rc == 0);

    /* check if it has been deleted */
    assert_false(torture_isdir(tmpdir));
}

int torture_run_tests(void) {
    int rc;
    UnitTest tests[] = {
        unit_test_setup_teardown(torture_sftp_mkdir, setup, teardown)
    };

    ssh_init();

    torture_filter_tests(tests);
    rc = run_tests(tests);
    ssh_finalize();

    return rc;
}
