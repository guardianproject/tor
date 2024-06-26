/* Copyright (c) 2019-2021, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#include "orconfig.h"

#include "core/or/or.h"
#include "feature/dirauth/process_descs.h"

#include "test/test.h"

static void
test_process_descs_versions(void *arg)
{
  (void)arg;
  struct {
    const char *version;
    bool should_reject;
  } cases[] = {
    // a very old version: reject.
    { "Tor 0.1.2.3-alpha", true },
    // a non-tor program: don't reject.
    { "Wombat 0.1.2.3-alpha", false },
    // some unsupported versions: reject.
    { "Tor 0.2.9.100", true },
    { "Tor 0.2.9.4-alpha", true },
    { "Tor 0.2.9.5-alpha", true },
    { "Tor 0.3.0.0-alpha-dev", true },
    { "Tor 0.3.0.2-alpha", true },
    { "Tor 0.3.0.5", true },
    { "Tor 0.3.1.4", true },
    { "Tor 0.3.2.4", true },
    { "Tor 0.3.3.4", true },
    { "Tor 0.3.4.1-alpha", true },
    { "Tor 0.3.4.100", true },
    { "Tor 0.3.5.1-alpha", true },
    { "Tor 0.3.5.6-rc", true},
    { "Tor 0.3.5.7", true },
    { "Tor 0.3.5.8", true },
    { "Tor 0.4.0.1-alpha", true },
    { "Tor 0.4.0.5", true },
    { "Tor 0.4.1.1-alpha", true },
    { "Tor 0.4.1.4-rc", true },
    { "Tor 0.4.1.5", true },
    { "Tor 0.4.2.1-alpha", true },
    { "Tor 0.4.2.4-rc", true },
    { "Tor 0.4.2.5", true },
    { "Tor 0.4.3.0-alpha-dev", true },
    { "Tor 0.4.3.8", true },
    { "Tor 0.4.4.9", true },
    { "Tor 0.4.5.5-rc", true },
    { "Tor 0.4.5.6", true },
    { "Tor 0.4.5.15", true },
    { "Tor 0.4.6.0-alpha-dev", true },
    { "Tor 0.4.6.1-alpha", true },
    { "Tor 0.4.6.5", true },
    { "Tor 0.4.6.50", true }, /* Non existing one in the 0.4.6 series */
    { "Tor 0.4.7.0-alpha-dev", true },
    { "Tor 0.4.7.3-alpha", true },
    { "Tor 0.4.7.12", true },

    /* The 0.4.8.x series is supported. */
    { "Tor 0.4.8.0-alpha-dev", false },
    { "Tor 0.4.8.2-alpha", false },
    { "Tor 0.4.8.3-rc", false },
    { "Tor 0.4.8.12", false },

    // Very far in the future
    { "Tor 100.100.1.5", false },
  };
  size_t n_cases = ARRAY_LENGTH(cases);

  for (unsigned i = 0; i < n_cases; ++i) {
    const char *msg = NULL;
    bool rejected = dirserv_rejects_tor_version(cases[i].version, &msg);
    tt_int_op(rejected, OP_EQ, cases[i].should_reject);
    tt_int_op(msg == NULL, OP_EQ, rejected == false);
  }

 done:
  ;
}

#define T(name,flags)                                   \
  { #name, test_process_descs_##name, (flags), NULL, NULL }

struct testcase_t process_descs_tests[] = {
  T(versions,0),
  END_OF_TESTCASES
};
