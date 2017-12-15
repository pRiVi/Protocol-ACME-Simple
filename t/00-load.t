#!perl -T
use 5.006;
use strict;
use warnings FATAL => 'all';
use Test::More;

plan tests => 1;

BEGIN {
    use_ok( 'Protocol::ACME::Simple' ) || print "Bail out!\n";
}

diag( "Testing Protocol::ACME::Simple $Protocol::ACME::Simple::VERSION, Perl $], $^X" );
