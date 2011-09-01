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
    plan(8);

    run_script("data/scripts/basic/no-krb", NULL, NULL);

    return 0;
}
