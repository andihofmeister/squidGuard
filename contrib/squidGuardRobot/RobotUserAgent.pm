package RobotUserAgent;

use Exporter;
use LWP::Parallel::UserAgent qw(:CALLBACK);
use POSIX qw(strftime);
@ISA = qw(LWP::Parallel::UserAgent Exporter);
@EXPORT = @LWP::Parallel::UserAgent::EXPORT_OK;

sub on_connect {
  my ($self, $request, $response, $entry) = @_;
  my ($key,$val);
  ::info("%s: %s", $request->{_method}, $request->{_uri});
}

1;
