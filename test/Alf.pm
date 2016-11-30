#
### ALF VERSION:XXX SVN:XXX
#
# A Living Framework - Elvin Tan (c) 2012
#
# Get the latest version from http://elvin.net/alf.pm
#
package Alf; 

use strict;
#use warnings;
no warnings;
use IO::Socket::INET;
use JSON;
use POSIX qw(:sys_wait_h ceil setsid);
use Net::SMTP;
use Net::Ping;
use Time::HiRes qw(gettimeofday tv_interval);
use Time::Local;
use Data::Dumper;
use File::Slurp;
$Data::Dumper::Useqq=1;

require Exporter;
our @ISA = qw(Exporter);
our %EXPORT_TAGS = ( 'all' => [ qw( debug LockGet LockRelease email pstat str2hex chr2hex asteroid leonid comma datetime apachedatetime isodate isodatetime isodatetime2 readJSON loadJSON loadINI syslog ansi filterusername filtermobile filterinput filterip filterdate filterdate2 filternumber filterflag getdate csv daemonize netbytes timeProfile filtertext doCron doQueue expandList shortenList binmac dotmac demac ppmac hexip unhexip packip udp slurpfile get_hardwareuuid fileChanged readTime humandate humandatelong humandateshort) ],
                     'lock' => [ qw ( LockGet LockRelease ) ],
                     'misc' => [ qw ( chr2hex comma datetime isodatetime loadJSON loadINI ) ]
                     );
our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );
our @EXPORT = qw( debug );

#############################################################################
##### Setup
#############################################################################

my $appname=$0;
$appname=~ s/(.+)\///i;

#############################################################################
##### Defaults
#############################################################################
%syslog::priorities = (
    EMER          => 0,  emerg         => 0, emergency     => 0,
    ALERT         => 1,  alert         => 1,
    CRITICAL      => 2,  crit          => 2,  critical      => 2,
    ERROR         => 3,  err           => 3,  error         => 3,
    WARN          => 4,  warning       => 4,
    NOTICE        => 5,  notice        => 5,
    INFO          => 6,  info          => 6, informational => 6,
    DEBUG         => 7,  debug         => 7,
    DUMP          => 7,
    RAW           => 7
);
@syslog::facilitylist=("kernel","user","mail","daemon","system","auth","syslog","lpr","news","uucp","cron","authpriv","ftp","NTP","audit","alert","clock2","local0","local1","local2","local3","local4","local5","local6","local7");

%syslog::facilities = (
    kern      => 0, kernel    => 0,
    user      => 1,
    mail      => 2,
    daemon    => 3,
    system    => 3,
    auth      => 4,
    syslog    => 5, internal  => 5,
    lpr       => 6, printer   => 6,
    news      => 7,
    uucp      => 8,
    cron      => 9, clock     => 9,
    authpriv  => 10, security2 => 10,
    ftp       => 11, FTP       => 11, 
    NTP       => 12,
    audit     => 13,
    alert     => 14,
    clock2    => 15,
    local0    => 16,
    local1    => 17,
    local2    => 18,
    local3    => 19,
    local4    => 20,
    local5    => 21,
    local6    => 22,
    local7    => 23,
);

#############################################################################
##### Meteorz
#############################################################################

sub asteroid {
  my $m=shift;
  my $server=shift || "127.0.0.1";
  $m=~ s/"/\\"/ig;
  my $remote = IO::Socket::INET->new( Proto     => "tcp",
                                      PeerAddr  => $server,
                                      PeerPort  => 4671
                                      );
  debug("[$$] ASTEROID $m",9); 
  if ($remote) {                                      
    $remote->autoflush(1);
    print $remote "ADDMESSAGE $m\n\n";
    close $remote;
  }
}  

sub leonid {
  my $m=shift;
  my $server=shift || "127.0.0.1";
  $m=~ s/"/\\"/ig;
  my $remote = IO::Socket::INET->new( Proto     => "udp",
                                      PeerAddr  => $server,
                                      PeerPort  => 4672
                                      );
#  debug("[$$] LEONID $m",9); 
  if ($remote) {                                      
    $remote->autoflush(1);
    print $remote "ADDMESSAGE $m";
    close $remote;
  }
}  

sub udp {
  my $m=shift;
  my $server=shift || "127.0.0.1";
  my $port=shift || 9999;
  my $remote = IO::Socket::INET->new( Proto     => "udp",
                                      PeerAddr  => $server,
                                      PeerPort  => $port
                                      );
  debug("[$$] UDP $m -> $server:$port",9); 
  if ($remote) {                                      
    $remote->autoflush(1);
    print $remote "$m";
    close $remote;
  }
}  

#############################################################################
##### Locking Function
#############################################################################

sub LockGet {
  my $lockfile=shift || "/tmp/$$.lock";
  if (-e "$lockfile") {
    open A,"$lockfile";
    my $pid=<A>;
    my $lasttime=<A>;
    chomp $pid;
    chomp $lasttime;
    close A;
    if ($pid==$$) { #myself ! DOPE ! (Or a 65536 PID loop.......)
      return 1;
    } elsif (kill 0 => $pid) { #still alive ?
      if (time() >= ($lasttime+10)) { # check last time;
        if (($pid != $$) && ($pid>0)) {
          debug("Timeout on lock on PID $pid with lasttime $lasttime",5);
          kill 9,$pid;
          open A,">$lockfile";
          print A "$$\n";
          close A;
          return 1;      
        } else {
          debug("Timeout on myself!",5);
          open A,">$lockfile";
          print A "$$\n";
          close A;
          return 1;      
        }
      } else {
        debug ("Give up on lock for PID $pid with lasttime $lasttime",4);
        return 0;
      }
    } else { #its mine !
      open A,">$lockfile";
      print A "$$\n";
      print A time()."\n";
      close A;
      return 1;    
    }
  } else {
    open A,">$lockfile";
    print A "$$\n";
    print A time()."\n";
    close A;
    return 1;
  }
}

sub LockRelease {
  my $lockfile=shift || "/tmp/$$.lock";
  if (-e "$lockfile") {
    open A,"$lockfile";
    my $pid=<A>;
    close A;
    if ($pid==$$) { #myself ! good !
      unlink "$lockfile";
      return 1;
    } elsif (kill 0 => $pid) { #still alive ?
      return 0;
    } else { #its mine !
      unlink "$lockfile";
      return 1;    
    }
  } else {
    return 1;
  }
}

#############################################################################
##### Logging Function (Exported)
#############################################################################
# $Global::DebugLevel=6; 
# 0 - Emergency, 1 - Alert, 2 - Crit, 3 - ERR, 4 - Warn, 5 - Notice, 6- Info, 7- Debug, 8-Dump, 9- Raw

sub debug {
  my $l=shift;
  my $level=shift;
  if (!defined $level) {
    $level=5;
  }  
#  my $caller=(caller(1))[3] || "";
#  if ($caller =~ /log$/i)  {
#    $caller=(caller(2))[3] || (caller(1))[3] || "";
#  }
  if (!defined $core::debug->{statuscode}) { 
    $core::debug->{statuscode}=\&Alf::_funcstatus;	 #External status message to add caller,etc if needed. Prototype below
  }
  if (($level<7) || ($core::config->{config}->{debug})) { #Only log if its level 6 and below, or in debug mode.
    my  ($time, $usec) = gettimeofday();
    my @a=localtime ($time);
    my @daylabel=("Sun","Mon","Tue","Wed","Thu","Fri","Sat");
    my @monthname=('Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec');
    #Filter $l
    #$l=~ s/[^a-zA-Z0-9\s\!\@\#\$\%\^&\*\(\)\\\/\-\+\=\_\{\}\[\]\:\;\"\'\,\.\<\>\?\~\`]/_/ig;
    $l =~ s/([\000-\037\177-\377])/<${\ord($1)}>/g;
    my $p=sprintf("%04d-%02d-%02d %02d:%02d:%02d,%03d %s %s\n",$a[5]+1900,$a[4]+1,$a[3],$a[2],$a[1],$a[0],$usec/1000,$core::debug->{statuscode}($l,$level),$l);
  # All logs will goto LogFile (Daily rotate)
    my $fds=sprintf("%04d%02d%02d",$a[5]+1900,$a[4]+1,$a[3]);
    if ($core::config->{config}->{DebugLogFolder}) {
      if ($core::config->{config}->{DebugLogFile}) {
        open A,">>".$core::config->{config}->{DebugLogFolder}."/".$core::config->{config}->{DebugLogFile};
        print A $p;
        close A;    
      } else {
        open A,">>".$core::config->{config}->{DebugLogFolder}."/".$appname.".".$fds.".log";
        print A $p;
        close A;
      }
    }
  # All logs will go to syslog if defined
    if ($core::config->{syslog}->{host}) {
      my @debuglevels=('EMER','ALERT','CRITICAL','ERROR','WARN','NOTICE','INFO','DEBUG','DUMP','RAW');
      syslog({"priority"=>$debuglevels[$level],"msg"=>sprintf("%s %s",$core::debug->{statuscode}($l),$l)});
    }
  # All logs go out via STDERR if more important then DebugLevel
    if ($level <= $Global::DebugLevel) {
      print STDERR $p;
    }
  }
}

sub _funcstatus {
  my $line=shift;
  my $level=shift;
  my $caller=(caller(2))[3] || ""; #Go up the stack, beyond debug call (1) is debug for sure.
  if ($caller =~ /log$/i)  {
    $caller=(caller(3))[3] || (caller(2))[3] || "";
  }
  if (length($caller)>32) {
    $caller=substr($caller,0,32);
  }
  my @debuglevels=(ansi(5).'EMER    '.ansi(-1),ansi(5).'ALERT   '.ansi(-1),ansi(1).'CRITICAL'.ansi(-1),ansi(3).'ERROR   '.ansi(-1),'WARN','NOTICE','INFO','DEBUG','DUMP','RAW');
  return sprintf("[%-32s] %-8s>",$caller,$debuglevels[$level]);
}

#############################################################################
##### Process/PID Functions
#############################################################################

sub pstat {
  my $t=shift || "vsize";
  if (-f "/proc/$$/stat") {
    open S,"/proc/$$/stat";
    my ($pid,$comm,$state,$ppid,$pgrp,$session,$tty_nr,$tpgid,$flags,
    $minflt,$cminflt,$majflt,$cmajflt,$utime,$stime,$cutime,$cstime, 
    $priority,$nice,$zero,$itrealvalue,$starttime,$vsize,$rss,$rlim, 
    $startcode,$endcode,$startstack,$kstkesp,$kstkeip,$signal,$blocked,
    $sigignore,$sigcatch,$wchan,$nswap,$cnswap,$exit_signal,$processor)= split(/\s+/,<S>);
    close S;  
    if ($t eq "vsize") {
      return $vsize;
    } elsif ($t eq "rss") {
      return $rss*POSIX::sysconf(&POSIX::_SC_PAGESIZE);
    } else {
      return 0;
    }
  } else {
    return 0;
  }
}  

#############################################################################
##### Email Functions
#############################################################################

sub email {
  my ($from,$to,$body)=(@_);
  open A,">>".$Global::LogFolder."/".$appname.".emails.log";
  print A "[$from -> $to]\n$body\n";
  close A;
  my $smtp = Net::SMTP->new('127.0.0.1');
   $smtp->mail($from);
   $smtp->to($to);
   $smtp->data();
   $smtp->datasend($body);
   $smtp->dataend();
   $smtp->quit;
}

#############################################################################
##### Misc Function
#############################################################################


sub chr2hex {
    my($c) = @_;
    return sprintf("\\x%02x", ord($c));
}

sub str2hex {
    my($c) = @_;
#    $c =~ s/(.)/sprintf("%02x",ord($1))/egx;
    return unpack("H*",  $c);
}

sub comma {
  my ($v)=(@_);
  $v=~ s/(^[-+]?\d+?(?=(?>(?:\d{3})+)(?!\d))|\G\d{3}(?=\d))/$1,/g;
  return $v;
}

sub datetime {
  my @a=localtime (shift || time());
  my @daylabel=("Sun","Mon","Tue","Wed","Thu","Fri","Sat");
  my @monthname=('Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec');
  return sprintf("%04d-%02d-%02d %02d:%02d:%02d %3s",$a[5]+1900,$a[4]+1,$a[3],$a[2],$a[1],$a[0],$daylabel[$a[6]]);
}

sub readTime { #returns time in seconds since epoch
  my $i=shift;
  if ($i=~ /(\d+)-(\d+)-(\d+) (\d+):(\d+):(\d+)/i) { #2015-10-05 10:36:08
    my $year=$1;
    my $mon=$2;
    my $mday=$3;
    my $hour=$4;
    my $min=$5;
    my $sec=$6;
    return timelocal( $sec, $min, $hour, $mday, $mon-1, $year )
  } elsif ($i=~ /(\d+)-(\d+)-(\d+) (\d+):(\d+)/i) { #2015-10-05 10:36
    my $year=$1;
    my $mon=$2;
    my $mday=$3;
    my $hour=$4;
    my $min=$5;
    my $sec=0;
    return timelocal( $sec, $min, $hour, $mday, $mon-1, $year )
  } elsif ($i=~ /(\d+)-(\d+)-(\d+)/i) {
    my $year=$1;
    my $mon=$2;
    my $mday=$3;
    return timelocal( 0,0,0, $mday, $mon-1, $year );
  } elsif ($i=~ /^(\d+)$/i) { #already timestamp
    return $i;
  }
}

sub humandate {
  my ($v)=(@_);
  my $t="later";
  $v=int($v);
  if ($v<0) {
    $v=-$v;
    $t="ago";
  }
  my $y=0;
  my $d=0;
  my $h=0;
  my $m=0;
  my $s=0;
  if ($v>(60*60*24*365)) {
    $y=int($v/(60*60*24*365));
    $v=$v % (60*60*24*365);
  }
  if ($v>(60*60*24)) {
    $d=int($v/(60*60*24));
    $v=$v % (60*60*24);
  }
  if ($v>(60*60)) {
    $h=int($v/(60*60));
    $v=$v % (60*60);
  }
  if ($v>60) {
    $m=int($v/60);
    $s=$v % 60;
    $v=0;
  }  
  if ($y>0) {
    return sprintf("%dy %dd %s",$y,$d,$t);
  } elsif ($d>0) {
    return sprintf("%dd %dh %s",$d,$h,$t);
  } elsif ($h>0) {
    return sprintf("%dh %dm %s",$h,$m,$t);
  } elsif ($m>0) {
    return sprintf("%dm %ds %s",$m,$s,$t);
  } else { 
    return sprintf("%ds %s",$v,$t);
  }
}

sub humandatelong {
  my ($v)=(@_);
  $v=int($v);
  my $y=0;
  my $d=0;
  my $h=0;
  my $m=0;
  my $s=0;
  if ($v>(60*60*24*365)) {
    $y=int($v/(60*60*24*365));
    $v=$v % (60*60*24*365);
  }
  if ($v>(60*60*24)) {
    $d=int($v/(60*60*24));
    $v=$v % (60*60*24);
  }
  if ($v>(60*60)) {
    $h=int($v/(60*60));
    $v=$v % (60*60);
  }
  if ($v>60) {
    $m=int($v/60);
    $s=$v % 60;
    $v=0;
  }  
  if ($y>0) {
    return sprintf("%dy %dd %dh %dm %ds",$y,$d,$h,$m,$s);
  } elsif ($d>0) {
    return sprintf("%dd %dh %dm %ds",$d,$h,$m,$s);
  } elsif ($h>0) {
    return sprintf("%dh %dm %ds",$h,$m,$s);
  } elsif ($m>0) {
    return sprintf("%dm %ds",$m,$s);
  } else {
    return sprintf("%ds",$v);
  }
}

sub humandateshort {
  my ($v)=(@_);
  $v=int($v);
  my $d=0;
  my $h=0;
  my $m=0;
  my $s=0;
  if ($v>(60*60*24)) {
    $d=int($v/(60*60*24));
    $v=$v % (60*60*24);
  }
  if ($v>(60*60)) {
    $h=int($v/(60*60));
    $v=$v % (60*60);
  }
  if ($v>60) {
    $m=int($v/60);
    $s=$v % 60;
    $v=0;
  }  
  if ($d>0) {
    return sprintf("%d days",$d);
  } elsif ($h>0) {
    return sprintf("%d hours",$h);
  } elsif ($m>0) {
    return sprintf("%d minutes",$m);
  } else {
    return sprintf("%d seconds",$v);
  }
}

sub isodate {
  my @a=localtime (shift || time());
  return sprintf("%04d-%02d-%02d",$a[5]+1900,$a[4]+1,$a[3]);
} 

sub nsedatetime {
  my @a=localtime (shift || time());
  return sprintf("%04d-%02d-%02dt%02d:%02d",$a[5]+1900,$a[4]+1,$a[3],$a[2],$a[1]);
} 

sub nsedatetime2 {
  my @a=localtime (shift || time());
  return sprintf("%04d-%02d-%02dT%02d:%02d:%02d",$a[5]+1900,$a[4]+1,$a[3],$a[2],$a[1],$a[0]);
} 

sub isodatetime {
  my @a=localtime (shift || time());
  return sprintf("%04d-%02d-%02d %02d:%02d:%02d",$a[5]+1900,$a[4]+1,$a[3],$a[2],$a[1],$a[0]);
} 

sub isodatetime2 {
  my @a=localtime (shift || time());
  return sprintf("%04d%02d%02d-%02d%02d%02d",$a[5]+1900,$a[4]+1,$a[3],$a[2],$a[1],$a[0]);
}
 
sub apachedatetime {
  my @a=localtime (shift || time());
  my @daylabel=("Sun","Mon","Tue","Wed","Thu","Fri","Sat");
  my @monthname=('Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec');
  return sprintf("%02d/%3s/%04d %02d:%02d:%02d %3s",$a[3],$monthname[$a[4]],$a[5]+1900,$a[2],$a[1],$a[0],$daylabel[$a[6]]);
}

sub readJSON {
  my $file=shift || "";
  if (-e $file){   
    my $data=slurpfile($file);
    eval { 
      return from_json($data);
      1;
    } or do {
      debug("File $file has bad JSON - $data",3);
      return;
    }
  } else {
    debug("File $file not found!",3);
  }
}


sub loadJSON {
  my $file=shift || "";
  my $sub=shift || "config";
  if (-f $file){   
    open S, $file; 
    my $json;
    while (<S>) {
      $json.=$_;  
    }
    close S;
    $core::config->{$sub}=from_json($json);
    debug(sprintf("[%d] Total of %0d elements loaded from %s",$$,scalar keys %{$core::config->{$sub}},$file),5);
  } else {
    debug("File $file not found!",3);
  }
}

sub loadINI {
  my $file=shift;
  my $sub=shift || "";
  if ($file) {
  } else {
    $file="$0.ini";
  }
  if (-e $file) {
    open I,"$file";
    my $section="config";
    $core::config->{ConfigCount}=0;
    while (<I>) {
      my $line=$_;
      chomp $line;
      if ($line =~ /^[;#]/i) {
      
      } elsif ($line =~ /^\s*\[(.+)\]/i) {
        $section=$1;
      } elsif ($line=~ /^\s*(.+?)\s*=\s*(.+)/i) {
        my $key=$1;
        my $value=$2;
        if ($key=~ /^"(.+)"$/i) {
          $key=$1;
        }
        if ($value=~ /^"(.+)"$/i) {
          $value=$1;
        }
        if ($sub) {
          $core::config->{$sub}->{$section}->{$key}=$value;
        } else {   
          $core::config->{$section}->{$key}=$value;
        }
        $core::config->{ConfigCount}++;
      }
    }
    debug("[$$] Loaded Config file $file with ".$core::config->{ConfigCount}." entries",5);
    close I;
  } else {
    print STDERR "Error: Failed to load Config file $file\n";
    return 0;
  }
}

sub syslog {
  my $ref=shift;
  if (($ref->{"host"}) || ($core::config->{syslog}->{host})) {
    my $facility_i = $syslog::facilities{ $ref->{"facilty"} || $core::config->{syslog}->{facility} } || 21;
    my $priority_i = $syslog::priorities{ $ref->{"priority"} || $core::config->{syslog}->{priority} } || 3;
    my $message = sprintf("<%s>%s[%0d]: %s",( ( $facility_i << 3 ) | ($priority_i) ),$ref->{app} || $core::config->{syslog}->{app} || $0,$$,$ref->{"msg"} );
    my $sock = new IO::Socket::INET(
        PeerAddr => $ref->{"host"} || $core::config->{syslog}->{"host"} || "127.0.0.1",
        PeerPort => $ref->{"port"} || $core::config->{syslog}->{"port"} || 514,
        Proto    => 'udp'
    );
    if ($sock) {
      print $sock $message;
    } 
    $sock->close();
  }
}



sub ansi {
  my $i=shift || "";   
  if ($i eq "") {
#    return "\033[1;32m\033[0m";
    return "\033[0m";
  } elsif ($i eq "reverse") {
    return "\033[7m";
  } elsif ($i eq "cls") {
    return "\033[2J";
  } elsif ($i eq "clear") {
    return "\033[K";
  } elsif ($i eq "save") {
    return "\033[s";
  } elsif (($i eq "restore") || ($i eq "load")) {
    return "\033[u";
  } elsif ($i eq "goto") {
    my $x=shift || 1;
    my $y=shift || 1;
    return sprintf("\033[%0d;%0df",$x,$y);
  } elsif ($i eq "hide") {
    return "\033[?25l\n";
  } elsif ($i eq "show") {
    return "\033[?25h\n";
  } elsif ($i <0) {
    return "\033[1;32m\033[0m";
  } else {
    my @colors=(30,31,32,33,34,35,36,37,30,30,40,41,42,43,44,45,46,47,40,40);
    $i=$i % 20;
    return "\033[1;".$colors[$i]."m";
  }
}


sub filterusername {
  my $l=shift;
  $l=~ s/[^a-zA-Z0-9\.\-\_\@]//ig;
  return $l;
}

sub filternumber {
  my $l=shift;
  $l=~ s/[^0-9\-]//ig;
  return $l;
} 

sub filtermobile {
  my $l=shift;
  $l=~ s/[^0-9]//ig;
  return $l;
} 
 
sub filterinput {
  my $l=shift;
  if ($l) {
 #                     ! @ # $ % ^ & * ( ) _ + - = { } [ ] " ` : ; < > , . ? ~ | \ / ' 
    $l=~ s/[^a-zA-Z0-9\!\@\#\$\%\^\&\*\(\)\_\+\-\=\{\}\[\]\"\`\:\;\<\>\,\.\?\~\|\\\/\']//ig;
    return $l;
  } else {
    return "";
  }
}

sub filtertext {
  my $l=shift;
  if ($l) {
#                        ! @ # $ % ^ & * ( ) _ + - = { } [ ] " ` : ; < > , . ? ~ | \ / ' 
    $l=~ s/[^a-zA-Z0-9\s\!\@\#\$\%\^\&\*\(\)\_\+\-\=\{\}\[\]\"\`\:\;\<\>\,\.\?\~\|\\\/\']//ig;
    return $l;
  } else {
    return "";
  }
}

sub filterflag {
  my $l=shift;
  if ($l) {
    return 1;
  } else {
    return 0;
  }
}
 
sub filterip {
  my $l=shift;
  $l=~ s/[^0-9\.\/]//ig;
  return $l;
}

sub filterdate {
  my $l=shift;
  if ($l=~ /(\d+)-(\d+)-(\d\d\d\d)/) {
    return sprintf("%04d-%02d-%02d",$3,$2,$1);
  } elsif ($l=~ /(\d\d\d\d)-(\d+)-(\d+)/) {
    return sprintf("%04d-%02d-%02d",$1,$2,$3);
  } else {
    return undef;
  }
}

sub filterdate2 {
  my $l=shift;
  if ($l=~ /(\d+)-(\d+)-(\d\d\d\d)/) {
    return sprintf("%02d-%02d-%04d",$1,$2,$3);
  } elsif ($l=~ /(\d\d\d\d)-(\d+)-(\d+)/) {
    return sprintf("%02d-%02d-%04d",$3,$2,$1);
  } else {
    return undef;
  }
}


sub ppmac {
  my $mac=shift || "00:00:00:00:00:00";
  $mac=~ s/://ig; 
  $mac=~ s/-//ig; 
  $mac=~ s/ //ig; 
  return uc($mac);
}

sub demac {
  my $mac=shift || "00:00:00:00:00:00";
  $mac=~ s/://ig; 
  $mac=~ s/-//ig; 
  $mac=~ s/ //ig; 
  return lc($mac);
}

sub binmac {
  return str2hex(shift);
}

sub dotmac {
  my $mac=shift || "00:00:00:00:00:00";
  $mac=demac($mac);
  if ($mac=~ /(..)(..)(..)(..)(..)(..)/) {
    return uc($1).":".uc($2).":".uc($3).":".uc($4).":".uc($5).":".uc($6);
  } else {
    return "00:00:00:00:00:00";
  }
}

sub hexip {
  my $ip=shift || "0.0.0.0";
  if ($ip=~ /(\d+)\.(\d+)\.(\d+)\.(\d+)/i) {
    return sprintf("%02X%02X%02X%02X",$1,$2,$3,$4);
  } else {
    return "00000000";
  }
}

sub unhexip {
  my $hexip=shift || "00000000";
  if ($hexip=~ /(..)(..)(..)(..)/i) {
    return sprintf("%0d.%0d.%0d.%0d",hex($1),hex($2),hex($3),hex($4))
  } else {
    return "0.0.0.0";
  }
}


sub sanitize {
  my $i=shift;
  $i=~ s/[^A-Za-z0-9\.\s,]//ig;
  return $i;
}


sub getdate {
  my $l=shift;
  if ($l=~ /(\d+)-(\d+)-(\d\d\d\d)/) {
    return ($3,$2,$1);
  } elsif ($l=~ /(\d\d\d\d)-(\d+)-(\d+)/) {
    return ($1,$2,$3);
  } else {
    return (undef,undef,undef);
  }
}

sub csv {
  my $c=shift;
  if ($c=~ /^(\d+)$/) {
    $c=~ s/"/\\"/;
    return '"'.$c.'"';
  } else {
    $c=~ s/"/\\"/;
    return '"'.$c.'"';
  }
  
}

sub netbytes {
 my $dev=shift || "eth0";
 open N,"/proc/net/dev";
 while (<N>) {
  chomp $_;
  if (/\s+(.+)\:\s*(\d+)\s+(\d+)\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+(\d+)\s+(\d+)/i) {
    if ($1 eq $dev) {
      close N;
      return ($2,$3,$4,$5);
    }
  }
 }
 close N;
 return (0,0,0,0);
}

sub daemonize {
               chdir '/'               or die "Can't chdir to /: $!";
               open STDIN, '/dev/null' or die "Can't read /dev/null: $!";
               open STDOUT, '>/dev/null'
                                       or die "Can't write to /dev/null: $!";
               defined(my $pid = fork) or die "Can't fork: $!";
               exit if $pid;
               setsid                  or die "Can't start a new session: $!";
               open STDERR, '>&STDOUT' or die "Can't dup stdout: $!";
}

sub timeProfile { 
  my @r;
  my $p;
  my $c=0;
  foreach my $i (@_) {
    if ($c>0) {
      if ($$i[2]>0) {
        push @r,sprintf("%20s - %12.6fs (Rate of %.3f/s)",$$i[1],tv_interval ( $p,$$i[0] ),$$i[2]/tv_interval ( $p,$$i[0] ));
      } else {    
        push @r,sprintf("%20s - %12.6fs",$$i[1],tv_interval ( $p,$$i[0] ));
      }
    }
    $p=$$i[0];
    $c++;
  }
  return @r;
}

sub doCron {
  my $cron=shift;
  foreach my $c (keys %{$cron}) {
    if (defined $cron->{$c}->{nexttime}) {
      if ($cron->{$c}->{nexttime}<=time()) {
        $cron->{$c}->{nexttime}=time()+$cron->{$c}->{timer};
        $cron->{$c}->{func}();
      }
    }else {
      $cron->{$c}->{nexttime}=time()+$cron->{$c}->{timer};
      $cron->{$c}->{func}();
    }
  }
}

sub doQueue {
  my $queue=shift;
  foreach my $c (keys %{$queue}) {
    if (defined $queue->{$c}->{nexttime}) {
      if ($queue->{$c}->{nexttime}<=time()) {
        my $nextfunc=$queue->{$c}->{func}; #buffer nextfunc
        delete $queue->{$c}; #delete previous queue.
        &{$nextfunc}(); #execute buffered nextfunc
      }
    } else {
      delete $queue->{$c};
    }
  }
}

sub statm {
	my $pid=int(shift) || $$;
  my $error = '';
  my $ref = {};
  if( ! open(_INFO,"</proc/$pid/statm") ){
    $error = "Couldn't open /proc/$pid/statm [$!]";
    return $ref;
  }
  my @info = split(/\s+/,<_INFO>);
  close(_INFO);
  $ref = {size     => $info[0] * 4,
          resident => $info[1] * 4,
          shared   => $info[2] * 4,
					text		 => $info[3] * 4,
					lib			 => $info[4] * 4,
					data		 => $info[5] * 4,
					dirty		 => $info[6] * 4};
  return $ref;
}

sub stat {
	my $pid=int(shift) || $$;
  my $error = '';
  my $ref = {};

  ### open and read the main stat file
  if( ! open(_INFO,"</proc/$pid/stat") ){
    $error = "Couldn't open /proc/$pid/stat [$!]";
    return $ref;
  }
  my @info = split(/\s+/,<_INFO>);
  close(_INFO);

  ### get the important ones
  $ref = {utime  => $info[13] / 100,
          stime  => $info[14] / 100,
          cutime => $info[15] / 100,
          cstime => $info[16] / 100,
          vsize  => $info[22],
          rss    => $info[23] * 4};

  return $ref;
}

sub old_statm {
  my $pid=int(shift) || 1;
  if (-f "/proc/$pid/statm") {
    open M,"/proc/$pid/statm";
#    my ($vmsize,$vmrss,$vmshar,$vmtext,$vmlib,$vmdata,$vmdirty)=split(" ",chomp(<M>));
    close M;
  }
}

sub expandList {
  my $in=shift;
  my @list;
  my $buffer;
  my $liststart;
  foreach my $i (0..length($in)-1) {
		my $c=substr($in,$i,1);
		if ($c=~ /\d/i) {
  		$buffer.=$c;
    } elsif ($c eq "-") {
      $liststart=int($buffer);
      $buffer="";
    } elsif ($c eq ",") {
      if ($liststart) {
        foreach my $i ($liststart..int($buffer)) {
          push @list,$i;
        }
        $liststart="";
      } else {
        push @list,int($buffer);
      }
      $buffer="";
    } else {
    }
	}
	if ($buffer) {
    if ($liststart) {
      foreach my $i ($liststart..int($buffer)) {
        push @list,$i;
      }
      $liststart="";
    } else {
      push @list,int($buffer);
    }
	  $buffer="";
	}
	return @list
}

sub shortenList {
  my @list=sort { $a <=> $b }  @_;
  my $final="";
  my $buffer="";
  my $prev="";  
  foreach my $i (@list) {
    my $cv=0;
    if ($i =~ /(\d+)/i) {
      $cv=$1;
    }
    if ($prev) {
      my $pv=0; 
      if ($prev =~ /(\d+)/i) {
        $pv=$1;
      }
      if ($pv==($cv-1)) { #Its a contination
        if ($buffer) { #There's something in buffer
        
        } else { #First item
          $buffer="$prev";  
        }      
      } else { # Big jump?
        if ($buffer) { # There's something in buffer
          $final.="$buffer-$prev,";
        } else {
          $final.="$prev,";
        }
        $buffer="";
      }
       
    }  
    $prev=$i;
  }
  if ($buffer) { #Flush last item in
    $final.="$buffer-$prev";
  } else {
    $final.="$prev";
  }
  return $final;
}

sub packip { #in . format
  my $addr=shift; 
  my @addrb=split("[.]",$addr);
  return pack( "C4",@addrb );
}

sub slurpfile {
  my $file=shift;
  my $data;
  if (-e $file) {
    return read_file($file);    
  } else {
    debug("Slurp failed - file $file doesn't exist.",3);
  }
}

sub readfile {
  my $file=shift;
  my $data;
  if (-e $file){   
    open S, $file; 
    while (<S>) {
      $data.=$_;  
    }
    close S;
	  return $data;
  } else {
    debug("Read failed - file $file doesn't exist.",3);
  }
}


sub get_hardwareuuid {
  if (-f "/sys/class/dmi/id/product_uuid") {
    open U,"/sys/class/dmi/id/product_uuid";
    my $uuid=<U>;
    chomp $uuid;
    close U;
    return $uuid;
  } elsif (-f "/sbin/blkid") { # mainly for centos 5
    if (my $uuid=`/sbin/blkid -t LABEL="/" -o value -s UUID`) {
      return uc($uuid);
    } elsif (my $uuid=`/sbin/blkid -t LABEL="root" -o value -s UUID`) {
      return uc($uuid);
    } elsif (my $uuid=`/sbin/blkid /dev/sda1 -o value -s UUID`) {
      return uc($uuid); 
    } elsif (my $uuid=`/sbin/blkid /dev/hda1 -o value -s UUID`) {
      return uc($uuid); 
    }
  }
  return "00000000-0000-0000-0000-000000000000"
}

sub fileChanged {	
  my $filename=shift;
  my $previousID=shift;
  if ((-f $filename) && (my ($dev,$ino,$mode,$nlink,$uid,$gid,$rdev,$size,$atime,$mtime,$ctime,$blksize,$blocks) = stat($filename))) {
    my $id=sprintf("%08X%08X",$ino,$mtime);
    if ($id eq $previousID) {
      return undef;
    } else {
      return $id;
    }
  } else {
    return undef;
  } 
}

1;
