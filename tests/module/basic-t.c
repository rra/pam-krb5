/*
 * Basic tests for the pam-krb5 module.
 *
 * This test case includes all tests that can be done without having Kerberos
 * configured and a username and password available.
 *
 * Written by Russ Allbery <rra@stanford.edu>
 * Copyright 2011
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * See LICENSE for licensing terms.
 */

#include <config.h>
#include <portable/system.h>

#include <tests/module/script.h>


int
main(void)
{
    struct script_config config;

    plan(8);

    memset(&config, 0, sizeof(config));
    run_script_dir("data/scripts/basic", &config);

    return 0;
}
