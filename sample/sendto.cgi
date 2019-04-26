#!/usr/bin/perl -w

use strict;
use CGI;

my $query = new CGI;
my $mode  = $query->url_param('mode');

if ($mode eq 'sendto') {
  my $host = $query->param('host');
  my $port = $query->param('port');
  my $protocol = $query->param('protocol');
  my $url = $query->param('url');
  my $request_file = $query->param('request');
  my $response_file = $query->param('response');

   eval {
      print "Content-Type: text/plain; charset=UTF-8\n\n";
      open OF, ">/tmp/list";
      print OF "== host ============================================================\n";
      print OF $host;
      print OF "\n";
      print OF "== port ============================================================\n";
      print OF $port;
      print OF "\n";
      print OF "== protocol ============================================================\n";
      print OF $protocol;
      print OF "\n";
      print OF "== url ============================================================\n";
      print OF $url;
      print OF "\n";
      print OF "== request [$request_file]============================================================\n";
      print OF &read_file($request_file);
      print OF "\n";
      print OF "== response [$response_file]============================================================\n";
      print OF &read_file($response_file);
      print OF "\n";
      print OF "==============================================================\n";
      close OF;
  };
  if ($@) {
      print "Error:$@";
  }

}
elsif ($mode eq 'list') {
    open IF, "/tmp/list";
    my @line = <IF>;
    close IF;

    print "Content-Type: text/plain; charset=UTF-8\n\n";
    foreach my $x (@line) {
      print $x;
    }

}

sub read_file() 
{
  my $IN = shift;
  binmode($IN);
  my $buf='';
  my $data = $buf;
  $data .= $buf while(read($IN,$buf,1000));
  return $data;
}

