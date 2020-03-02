/*
 * Basic tests for the pam-krb5 module.
 *
 * This test case includes all tests that can be done without having Kerberos
 * configured and a username and password available, and without any special
 * configuration.
 *
 * Written by Russ Allbery <eagle@eyrie.org>
 * Copyright 2020 Russ Allbery <eagle@eyrie.org>
 * Copyright 2011
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * SPDX-License-Identifier: BSD-3-clause or GPL-1+
 */

#include <config.h>
#include <portable/system.h>

#include <tests/fakepam/script.h>
#include <tests/tap/basic.h>
#include <tests/tap/kerberos.h>


int
main(void)
{
    struct script_config config;

    plan_lazy();

    /*
     * Generate a testing krb5.conf file with a nonexistent default realm so
     * that this test will run on any system.
     */
    kerberos_generate_conf("bogus.example.com");

    /* Attempt login as the root user to test ignore_root. */
    memset(&config, 0, sizeof(config));
    config.user = "root";

    run_script_dir("data/scripts/basic", &config);

    return 0;
}
