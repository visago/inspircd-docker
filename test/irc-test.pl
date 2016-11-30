#!/usr/bin/perl
require 5.10.0;
use strict;
use warnings;
use Fcntl;
use POSIX ":sys_wait_h";
use MyTCP;
use Time::HiRes qw( usleep ualarm gettimeofday tv_interval );
use Data::Dumper;
use POSIX qw(ceil);
use Alf qw( :all);
use JSON;
use Socket;

require 'sys/ioctl.ph';

$SIG{CHLD} = \&REAPER;
$SIG{INT} = sub { die "Caught a sigint $!" };
$SIG{TERM} = sub { die "Caught a sigterm $!" };

undef $core::config->{config}->{LogFolder};
undef $core::config->{config}->{DebugLogFolder};
#$core::config->{config}->{debug}=6; #needed to log debug>7
$Global::DebugLevel=9;
$core::config->{config}->{debug}=9;

########################### EDIT NOTHING BELOW ###################################
my $version="0.1";
my $timeout=10;
my $retries=0;

my $md5=md5file($0);
my $tcpd=new MyTCP(jitterwarning=>300,maxconnections=>128,handler=>{"irc"=>{connect=>\&connect_irc, disconnect=>\&disconnect_irc, line=>\&processline_irc}});

my $irc;
$irc->{user}=$ENV{'HOSTNAME'} || "botcc";
$irc->{nick}=$ENV{'DIMSUM_USER'} || "test$$";
$irc->{desc}=sprintf("HOSTNAME: %s",$ENV{'HOSTNAME'} || "XXXXXXXXXX");
$irc->{ircserver}=$ENV{'DIMSUM_SERVERIP'} || "127.0.0.1";
$irc->{ircport}=$ENV{'DIMSUM_SERVERPORT'} || "6667";
$irc->{starttime}=time();
$irc->{timeout}=0;
$irc->{command}=0;
$irc->{lastping}="999.999";
$irc->{fd}=0;


my $cron;
$cron->{ping}->{func}=\&cron_ping;
$cron->{ping}->{timer}=60;

my $queue;
$queue->{start}->{nexttime}=time();
$queue->{start}->{func}=\&irc_start;
  
my $running=1;
while ($running) { 
  ### PERFORM READS/ACCEPT TO BUFFER
  my $t0 = [gettimeofday];
  $tcpd->loop(0.9);
  doCron($cron);
  doQueue($queue);
  my $elapsed = tv_interval ( $t0, [gettimeofday]);
  if ($elapsed>240) {
    debug(sprintf("LAG ! Took %.3fs",$elapsed),4);
  }
  if (($irc->{timeout}) && (time()>$irc->{timeout})) {
    debug(sprintf("Timed Out !"),4);
    $running=0;
  }
}
exit 0;

sub irc_start {
  $tcpd->connect($irc->{ircserver},$irc->{ircport},"irc");
}
sub cron_ping {
  if ($irc->{fd}) {
     $tcpd->send($irc->{fd},sprintf("PING :%s.%s [%s]",gettimeofday,dts()));
#     debug(spritf("We got %0d users in %s".scalar keys %{$irc->{channel}->{$irc->{clusterchannel}}},$irc->{clusterchannel}),4);
  }	
}


sub dcmi_msg {
  my $msg=shift;
  if ($irc->{fd}) {
    $tcpd->send($irc->{fd},sprintf("PRIVMSG #dcmi %s",$msg));      
  }
}

sub accept { #This routine is called whenever a TCP connection is opened by Server
  my $tcpd=shift;
  my $fd=shift;
  $tcpd->{tcpd}->{tcp}->{$fd}->{state}=1;
}

sub disconnect_irc { #This routine is called whenever a TCP connection is disconnected
  my $tcpd=shift;
  my $fd=shift;
  my $retry=10;
   debug(sprintf("[%5d] Disconnected - Will retry to connect in %dsec !",$fd,$retry),5);
   $queue->{start}->{nexttime}=time()+$retry;
   $queue->{start}->{func}=\&irc_start;
}

sub connect_irc { #This routine is called whenever a TCP connection is connected from app
  my $tcpd=shift;
  my $fd=shift;
  $tcpd->{tcpd}->{tcp}->{$fd}->{state}=1;
  $tcpd->send($fd,sprintf("USER %s HOST SERVER %s",$irc->{user},$irc->{desc}));
  $tcpd->send($fd,sprintf("NICK %s",$irc->{nick}));  
}

sub processline_irc { # Main line processor. Called with file descriptor and line received.
  my $tcpd=shift;
  my $fd=shift;
  my $line=shift;
  chomp($line);
  $line=~ s/\x0d$//i;
  debug(sprintf("[%5d] Process '%s'",$fd,$line),7);
  
  if ($line=~ /:(.+?) 433 (.+?) (.+?) :(.+)/) {
    # Already running. Quit.
    debug(sprintf("[%5d] Another IRC process already running. Quiting...",$fd),4);
    exit;
    my $last=substr($irc->{nick},length($irc->{nick})-1,1);
    if ( $last=~ /\d+/i) {
      $irc->{nick}=$irc->{nick}."a";
    } else {
      $irc->{nick}=substr($irc->{nick},0,length($irc->{nick})-1).chr(ord($last)+1);
    }
    $tcpd->send($fd,sprintf("NICK %s",$irc->{nick}));  
  } elsif ($line=~ /:(.+?) 001 (.+?) :(.+)/i) {
    my $server=$1;
    my $mynick=$2;
    my $welcome=$3;
    $irc->{fd}=$fd;
    $irc->{nick}=$mynick;
    $tcpd->send($fd,"JOIN #all");
    $tcpd->send($fd,"JOIN #dcmi");
    $tcpd->send($fd,"JOIN #".$irc->{cluster});
    cron_ping(); #Just to trigger start
  } elsif ($line=~ /:(.+?) 353 (.+?) \= (.+?) :(.+)/i) {
    my $server=$1;
    my $mynick=$2;
    my $chan=$3;
    my $users=$4;
    debug("[User List $chan] $users",4);
  } elsif ($line=~ /:(.+?) PART :(.+)/i) {
    my $user=$1;
    my $chan=$2;
    my $nick=getNick($user);
    if (defined $irc->{channel}->{$chan}->{$nick}) {
      delete $irc->{channel}->{$chan}->{$nick};
    }
  } elsif ($line=~ /:(.+?) JOIN :(.+)/i) {
    my $user=$1;
    my $chan=$2;
    $irc->{channel}->{$chan}->{getNick($user)}=$user;
    if ($irc->{nick} eq getNick($user)) { #Its me joining !
      if ($chan eq "#dcmi") {
      }
    }
  } elsif ($line=~ /:(.+?) KICK (.+?) (.+) :(.+)/i) { #:alf!alf@192.168.1.69 KICK #test user01 :blah
    my $user=$1;
    my $chan=$2;
    my $nick=$3;
    my $reason=$4;
    debug(sprintf("[%5d] IRC: %s kicked %s from %s (Reason: %s)",$fd,$user,$nick,$chan,$reason),5);
    if ($irc->{nick} eq $nick) { #Auto rejoin
      $tcpd->send($fd,sprintf("JOIN %s",$chan));
    }
  } elsif ($line=~ /:(.+?) PRIVMSG (.+?) :(.+)/i) {
    my $from=$1;
    my $target=$2;
    my $msg=$3;
    my $nick=getNick($from);
    my $user=getUser($from);
    my $reply=getNick($from);
    if ($target =~ /^#/i) {
      $reply=$target;
    }
    if ($target eq "#".$irc->{cluster}) {
      debug(sprintf("[%5d] LOG/CLIENT $nick - %s",$fd,$msg),4);
    } elsif ($target eq $irc->{nick}) { #msg to me ! 
      debug(sprintf("[%5d] IRC: %s PRIVMSG to %s - %s",$fd,$from,$target,$msg),6);
    } else {
     debug(sprintf("[%5d] IRC: %s PRIVMSG to %s - %s",$fd,$from,$target,$msg),6);
    }
  } elsif ($line=~ /:(.+?) PONG (.+?) :(\d+)\.(\d+)/i) {
    my $from=$1;
    my $pong=$3;
    $irc->{lastping}=tv_interval([$3,$4]);
    $irc->{lasttime}=[$3,$4];   
  } elsif ($line=~ /PING :(.+)/i) {
    my $ping=$1;
    $tcpd->send($fd,sprintf("PONG :%s",$ping));
  } elsif ($line=~ /:(.+?) QUIT :(.+)/i) {
    my $from=$1;
    my $nick=getNick($from);
    my $user=getUser($from);
    my $reply=getNick($from);
  } else {
#    debug("Unhandled - $line",3)
  }
}

sub isMaster {
  my $nick=shift;
  if ($nick =~ /(.+?)\!(.+)\@(.+)/i) { #alf!alf@192.168.1.69
    my $nick=$1;
    my $user=$2;
    my $ip=$3;
  }
  return 1;
}

sub decol {
  my $l=shift;
  $l=~ s/^://ig;
  return $l;
}

sub getNick {
  my $from=shift;
  if ($from =~ /(.+?)\!(.+)\@(.+)/i) { #alf!alf@192.168.1.69
    return $1;
  } else {
    return $from;
  }
}

sub getHost {
  my $from=shift;
  if ($from =~ /(.+?)\!(.+)\@(.+)/i) { #alf!alf@192.168.1.69
    return $3;
  } else {
    return $from;
  }
}

sub getUser {
  my $from=shift;
  if ($from =~ /(.+?)\!(.+)\@(.+)/i) { #alf!alf@192.168.1.69
    return $2;
  } else {
    return $from;
  }
}

sub md5file {
  my $file=shift;
  my $md5 = Digest::MD5->new;
  if (-f $file) {
   open M,$file; 
   $md5->addfile(*M);
   close M;
  }
  return $md5->hexdigest;
}

sub dts {
    my @a=localtime(time());
    return sprintf("%04d-%02d-%02d %02d:%02d:%02d",$a[5]+1900,$a[4]+1,$a[3],$a[2],$a[1],$a[0]);
}

sub REAPER {
  my $child;
  while (($child = waitpid(-1,WNOHANG)) > 0) {
  }
  $SIG{CHLD} = \&REAPER;  # still loathe sysV

}

sub get_interface_address
{
    my ($iface) = @_;
    my $socket;
    socket($socket, PF_INET, SOCK_STREAM, (getprotobyname('tcp'))[2]) || die "unable to create a socket: $!\n";
    my $buf = pack('a256', $iface);
    if (ioctl($socket, SIOCGIFADDR(), $buf) && (my @address = unpack('x20 C4', $buf)))
    {
        return join('.', @address);
    }
    return undef;
}

