package Protocol::ACME::Simple;

use strict;
use Protocol::ACME;
use Protocol::ACME::Challenge::LocalFile;
use x509factory::X509Factory qw(
   $TYPSERVER
);

our $VERSION = "0.01";

my $debug = 0;

sub getHostPrefix {
   my $host = shift;
   return $host ?
    ((ref($host) eq "ARRAY") ?
         ($host->[0] ?
          $host->[0]."." : "")
      : $_.".")
   : ""
}

sub makeAcme {
   my $domain = shift;
   my $accountkey = shift;
   my $hosts = shift || [""];
   my $config = shift || {};

   my $config = {
      country      => "DE",
      state        => "Germany",
      location     => "Augsburg",
      organisation => "CryptoMagic GmbH",
      comment      => "CryptoMagic Webservercertificate",
      days         => 90,
      pass         => "1234",
      %$config,
      commonname   => $domain,
      commonaltnames => [map { getHostPrefix($_).$domain } @$hosts],
      serial       => "01", # Das naechsthoere wird genommen!
      onlycsr      => 1,
   };
   $config->{flags} = $TYPSERVER
      unless(defined($config->{flags}));

   my $result = x509factory::X509Factory::createCertificate($config);
   return $result->{err} ? $result : {err => "Got no CSR !"}
      if (!$result->{csr} || $result->{err});
   print "CSR:".length($result->{csr})."\n"
      if $debug;

   my $return = {
      %$result,
   };

   unless ($noacme) {
      my $acme = undef;
      eval {
         #print "REF:".$accountkey.":".ref($accountkey).":".$$accountkey.":\n";
         die "account.key missing: Read ACME specifications!".$accountkey.".".ref($accountkey)
            unless (ref($accountkey) || -f $accountkey);
         #print "Account key: ".$accountkey."\n";
         $acme = Protocol::ACME->new(
            host        => 'acme-v01.api.letsencrypt.org',
            account_key => $accountkey,
            debug       => 1,
         );
         print "Directory"
            if $debug;
         $acme->directory();
         print "Register\n"
            if $debug;
         $acme->register();
         print "TOS\n"
            if $debug;
         $acme->accept_tos();
         foreach my $host (@$hosts) {
            my $curdomain = getHostPrefix($host).$domain;
            print "Domain:".$curdomain."\n"
               if $debug;
            print "Auth\n"
               if $debug;
            $acme->authz( $curdomain );
            my $curChallenge = ((ref($host) eq "ARRAY") && $host->[1]) ?
                                                           $host->[1] : Protocol::ACME::Challenge::LocalFile->new({www_root => "/var/www/html"});
            print "Challenge\n"
               if $debug;
            $acme->handle_challenge($curChallenge);
            print "Check\n"
               if $debug;
            $acme->check_challenge();
            print "Cleanup\n"
               if $debug;
            $acme->cleanup_challenge($curChallenge);
         }
      };
      if ( $@ ) {
         return {%$result, err => UNIVERSAL::isa($@, 'Protocol::ACME::Exception') ? "Not saving/updating: Error occurred: Status: ".$@->{status}." Detail: ".$@->{detail}." Type:   ".$@->{type} : $@};
      } else {
         my $cert = undef;
         eval {
            $cert = $acme->sign( \$result->{csr} );
         };
         if ( $@ ) {
            return {%$result, err => UNIVERSAL::isa($@, 'Protocol::ACME::Exception') ? "Not saving/updating: Error occurred: Status: ".$@->{status}." Detail: ".$@->{detail}." Type:   ".$@->{type} : $@};
         } else {
            # do something appropriate with the DER encoded cert
            return {%$result, cert => $cert};
         }
      }
   }
}

__END__

=head1 NAME

Protocol::ACME::Simple - ACME with certificates made simple

=head1 VERSION

Version 0.01

=head1 DESCRIPTION

Let's encrypts ACME with certificates made simple

=cut

1;

