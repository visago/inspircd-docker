#!/usr/bin/perl
#
#
# ulimit -n 
#
#
package MyTCP; 
use strict;
#use warnings;
use strict;
use warnings;
use IO::Select;
use IO::Socket;
use Time::HiRes qw( usleep ualarm gettimeofday tv_interval );
use Fcntl qw(F_GETFL F_SETFL O_NONBLOCK);
use Data::Dumper;
#use Digest::HMAC_SHA1 qw(hmac_sha1 hmac_sha1_hex);
use Digest::MD5 qw(md5 md5_hex md5_base64);
use Alf qw(:all);

require Exporter;
our @ISA = qw(Exporter);
our %EXPORT_TAGS = (  'all' => [ qw( ) ] );
our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );
our @EXPORT = qw( );

#############################################################################
##### Setup Options
#############################################################################

sub new {
  my $proto = shift;
  my $class = $proto;

  my %args = @_ ;
  my $self ={};
  bless( $self, $class );
  $self->{tcpd}->{selects} = new IO::Select(); # create handle set for reading
  $self->{maxconnections}=$args{maxconnections} || 256; #maximum number of allowed TCP connections
  $self->{stimeout}=$args{stimeout} || 0.1;  #select timeouts. Must be half of $self->{tcptimeout} !
  $self->{jitterwarning}=$args{jitterwarning} || 1.0; #minimum time between sections before warnings
  $self->{crlf}=$args{crlf} || "\n"; #CRLF value to use.
  $self->{tcptimeout}=$args{tcptimeout} || 300; #timesout after X seconds of inactivity
  $self->{chunksize}=$args{chunksize} || 32768;
  $self->{handler}=$args{handler};
  $self->{handler}->{default}->{accept}= \&_funcaccept; #Called when a listening socket accepts
  $self->{handler}->{default}->{line}=\&_funcline; #Called for each line of data coming in
  $self->{handler}->{default}->{raw}=\&_funcraw; #Called for each line of data coming in
  $self->{handler}->{default}->{connect}= \&_funcconnect; #Called when an outgoing socket connects 
  $self->{handler}->{default}->{disconnect}= \&_funcdisconnect; #Called when a socket disconnects 
  if ($self->{maxconnections}>getFD()) {
    debug(sprintf("%0d limit requested but only max of %0d fds. (Use 'ulimit -n %0d')",$self->{maxconnections},getFD(),$self->{maxconnections}+512),2);
  }
  return $self;
}

#######################################################################
################# CONNECTION / APPLICATION VARIABLES  #################
#######################################################################

sub loop {
  my $self=shift;
  my $timeout=shift || 0;
  my $t0;
  my $elapsed;
  ### PERFORM READS/ACCEPT TO BUFFER
  my ($readhandles,$writehandles);
  my $writecount=$self->writecount();
  if ($writecount>0) {
    ($readhandles,$writehandles)=IO::Select::select($self->{tcpd}->{selects},$self->{tcpd}->{selects},undef,$timeout || $self->{stimeout});
  } else {
    ($readhandles)=IO::Select::select($self->{tcpd}->{selects},undef,undef,$timeout || $self->{stimeout});
  }
  $t0 = [gettimeofday];
  foreach my $handle (@{$readhandles}) { #fill read buffer 
    my $fd=fileno $handle;
    if ($self->{tcpd}->{tcp}->{$fd}->{type}==2) { #new connection from a master/listening
      if ($self->{tcpd}->{selects}->count()>$self->{maxconnections}) {
        my $newsocket = $handle->accept();
        fcntl($newsocket,F_SETFL,O_NONBLOCK);
#        $self->opensocket($newsocket);
        debug(sprintf("[%5d] DENIED CONNECTION. LIMIT OF %0d HIT",$fd,$self->{maxconnections}),4);
        $self->closesocket($newsocket);        
      } else {
        if ($self->{tcpd}->{tcp}->{$fd}->{proto} eq "udp") {
          debug(sprintf("[%5d] UDP Socket trying to do an accept. Set Type !!",$fd),3);
        } else {
          my $newsocket = $handle->accept();
          if ($newsocket) {
            $self->{tcpd}->{tcp}->{$fd}->{clients}++;
            $self->{tcpd}->{tcp}->{$fd}->{clientsps}++;
            $self->opensocket($newsocket);
            $self->{tcpd}->{tcp}->{fileno $newsocket}->{parentfd}=$fd;
            my $handler=$self->{tcpd}->{tcp}->{$fd}->{handler};
            $self->{tcpd}->{tcp}->{fileno $newsocket}->{handler}=$handler;
            if (defined $self->{handler}->{$handler}->{accept}) {
              $self->{handler}->{$handler}->{accept}($self,fileno $newsocket);
            } else {
              $self->{handler}->{default}->{accept}($self,fileno $newsocket);
            }
          } else {
            debug(sprintf("[%5d] FAILED TO ACCEPT NEW CONNECTION.",$fd),3);
          }
        }
      }
    } elsif ($self->{tcpd}->{tcp}->{$fd}->{type}==3) { #packet processor for udp
      my $buffer;
      my $handler=$self->{tcpd}->{tcp}->{$fd}->{handler} || "default";
      my $parentfd=$self->{tcpd}->{tcp}->{$fd}->{parentfd} || 0;
#      my $peerhost;
      if (my $peerhost=recv($handle,$buffer,$self->{chunksize},0)) {
        $self->{tcpd}->{tcp}->{$fd}->{lasttime}=time();
        my $length=length $buffer;
        if ($length) {
          my($peer_port, $ipaddr) = sockaddr_in($peerhost);
          my $peer_address = inet_ntoa ($ipaddr);
          debug(sprintf("[%5d] READ %0d BYTES FROM %0s:%0d.",$fd,$length,$peer_address,$peer_port),8);
          debug(sprintf("[%5d] READ '%s' FROM %0s:%0d",$fd,$buffer,$peer_address,$peer_port),9);
#          $self->{tcpd}->{tcp}->{$fd}->{readbuffer}.=$buffer; #We never fill buffer
          $self->{tcpd}->{tcp}->{$fd}->{readbytes}+=$length;
          $self->{tcpd}->{tcp}->{$fd}->{readbps}+=$length;
          if ($parentfd) {
            $self->{tcpd}->{tcp}->{$parentfd}->{readbytes}+=$length;
            $self->{tcpd}->{tcp}->{$parentfd}->{readbps}+=$length;
          }
          if (defined $self->{handler}->{$handler}->{line}) {
            $self->{handler}->{$handler}->{line}($self,$fd,$buffer,$peer_address,$peer_port);
          } else {
            $self->{handler}->{default}->{line}($self,$fd,$buffer,$peer_address,$peer_port);
          }
#          $self->{tcpd}_readfps[$fd]++;
        } else { # 0 byte read. D/C 
          debug(sprintf("[%5d] ZERO BYTE READ - UDP ERROR !",$fd),4);
          $self->closesocket($handle);
        }
      } else {
        debug(sprintf("[%5d] UDP ERROR: %s",$fd,$!),3);
        $self->closesocket($handle);
      }
    } else {
      my $buffer;
      my $handler=$self->{tcpd}->{tcp}->{$fd}->{handler} || "default";
      my $parentfd=$self->{tcpd}->{tcp}->{$fd}->{parentfd} || 0;
      if (defined recv($handle,$buffer,$self->{chunksize},0)) {
        $self->{tcpd}->{tcp}->{$fd}->{lasttime}=time();
        my $length=length $buffer;
        if ($length) {
          debug(sprintf("[%5d] READ %0d BYTES.",$fd,$length),8);
          debug(sprintf("[%5d] READ '%s'",$fd,$buffer),9);
          $self->{tcpd}->{tcp}->{$fd}->{readbuffer}.=$buffer;
          $self->{tcpd}->{tcp}->{$fd}->{readbytes}+=$length;
          $self->{tcpd}->{tcp}->{$fd}->{readbps}+=$length;
          if ($parentfd) {
            $self->{tcpd}->{tcp}->{$parentfd}->{readbytes}+=$length;
            $self->{tcpd}->{tcp}->{$parentfd}->{readbps}+=$length;
          }
          if ($self->{tcpd}->{tcp}->{$fd}->{type}==4) { #raw notify !
            if (defined $self->{handler}->{$handler}->{raw}) {
              $self->{handler}->{$handler}->{raw}($self,$fd,$buffer,$self->{tcpd}->{tcp}->{$fd}->{readbuffer});
            } else {
              $self->{handler}->{default}->{raw}($self,$fd,$buffer,$self->{tcpd}->{tcp}->{$fd}->{readbuffer});
            }          
          }
#          $self->{tcpd}_readfps[$fd]++;
        } else { # 0 byte read. D/C
          debug(sprintf("[%5d] ZERO BYTE READ",$fd),7);
          $self->closesocket($handle);
        }
      } else {
        debug(sprintf("[%5d] ERROR: %s",$fd,$!),3);
        $self->closesocket($handle);
      }
    }
  }
  $elapsed = tv_interval ( $t0, [gettimeofday]);
  if ($elapsed>$self->{jitterwarning}) {
    debug(sprintf("[%5d] ACCEPT JITTER OF %.1f SECONDS",0,$elapsed),5);
  }

  ### PERFORM WRITES FROM BUFFER
  $t0 = [gettimeofday];
  foreach my $handle (@{$writehandles}) { #process write buffer;
    my $fd=fileno $handle;
    if ($fd) {
      my $handler=$self->{tcpd}->{tcp}->{$fd}->{handler} || "default";
      if ($self->{tcpd}->{tcp}->{$fd}->{type}==2) {
        debug(sprintf("[%5d] Cant Write to Master Socket",$fd),3);
      } else {
        my $parentfd=$self->{tcpd}->{tcp}->{$fd}->{parentfd} || 0;
        if ($self->{tcpd}->{tcp}->{$fd}->{writebuffer}) {
          my $line=$self->{tcpd}->{tcp}->{$fd}->{writebuffer};
          my $el=length $line;
          my $l=send($handle,$line,0);
          if ($l) {
            $self->{tcpd}->{tcp}->{$fd}->{lasttime}=time();
            $self->{tcpd}->{tcp}->{$fd}->{writebytes}+=$l;
            debug(sprintf("[%5d] WRITE %0d BYTES.",$fd,$l),8);
            $self->{tcpd}->{tcp}->{$fd}->{writebps}+=$l;
            $self->{tcpd}->{tcp}->{$fd}->{writefps}++;
            if ($parentfd) {
              $self->{tcpd}->{tcp}->{$parentfd}->{writebytes}+=$l;
              $self->{tcpd}->{tcp}->{$parentfd}->{writebps}+=$l;
              $self->{tcpd}->{tcp}->{$parentfd}->{writefps}++;
            }

            if ($l != $el) {  
              $self->{tcpd}->{tcp}->{$fd}->{writebuffer}=substr($line,$l);
              my $cl=length $self->{tcpd}->{tcp}->{$fd}->{writebuffer};
              debug(sprintf("[%5d] Sent %0d bytes, expected %0d bytes. Buffer left with %0d bytes.",$fd,$l,$el,$cl),7);
            } else {
              $self->{tcpd}->{tcp}->{$fd}->{writebuffer}="";
            }
          } else {
            debug(sprintf("[%5d] Tried to send %0d bytes. Failed.",$fd,$el),3);
            $self->closesocket($handle);
          }
        }

      }
    }
  }
  $elapsed = tv_interval ( $t0, [gettimeofday]);
  if ($elapsed>$self->{jitterwarning}) {
    debug(sprintf("[%5d] WRITE JITTER OF %.1f SECONDS",0,$elapsed),5);
  }

  ### PROCESS READ BUFFER
  $t0 = [gettimeofday];
  foreach my $handle ($self->{tcpd}->{selects}->handles()) { #process read buffer
    my $fd=fileno $handle;
    if ($fd) { #This should rarely be an issue.. lol..
      my $handler=$self->{tcpd}->{tcp}->{$fd}->{handler} || "default";
      if (($self->{tcpd}->{tcp}->{$fd}->{type} != 2) && ($self->{tcpd}->{tcp}->{$fd}->{type} != 4)) { # No buffer for 2 (master) and 4(raw/manual)
        my $parentfd=$self->{tcpd}->{tcp}->{$fd}->{parentfd} || 0;
  #      while ($self->{tcpd}_readbuffer[$fd]=~ s/(.+?)([\r\n]+)//i) {
  #        my $line=$1;
        while ((my $i=index($self->{tcpd}->{tcp}->{$fd}->{readbuffer},"\n"))>0) {
          if ($i>=0) {
            my $line=substr($self->{tcpd}->{tcp}->{$fd}->{readbuffer},0,$i);
            $self->{tcpd}->{tcp}->{$fd}->{readbuffer}=substr($self->{tcpd}->{tcp}->{$fd}->{readbuffer},$i+1);
            my $length=length $line;
            debug(sprintf("[%5d] PROCESS %0d / %0d BYTES.",$fd,$length,$i),8);
            debug(sprintf("[%5d] PROCESSED '%s'",$fd,$line),9);
            $self->{tcpd}->{tcp}->{$fd}->{readfps}++;            
            $self->{tcpd}->{tcp}->{$parentfd}->{readfps}++;
            if (defined $self->{handler}->{$handler}->{line}) {
              $self->{handler}->{$handler}->{line}($self,$fd,$line);
            } else {
              $self->{handler}->{default}->{line}($self,$fd,$line);
            }
          }
        }
      }
    }
  }
  $elapsed = tv_interval ( $t0, [gettimeofday]);
  if ($elapsed>$self->{jitterwarning}) {
    debug(sprintf("[%5d] READ JITTER OF %.1f SECONDS",0,$elapsed),5);
  }
  
  ### PERFORM CONNECTION LOOPS (IF ANY)
  $t0 = [gettimeofday];
  foreach my $handle ($self->{tcpd}->{selects}->handles()) {
    my $fd=fileno $handle;
    my $handler=$self->{tcpd}->{tcp}->{$fd}->{handler} || "default";
    if (($self->{tcpd}->{tcp}->{$fd}->{type}==2) || ($self->{tcpd}->{tcp}->{$fd}->{type}==3)) {  # Master / Listen Socket
    } else {      # Client Sockets
      if ($self->{tcpd}->{tcp}->{$fd}->{state}==8) { #Wants to close, need to ensure buffer is empty
        if (length($self->{tcpd}->{tcp}->{$fd}->{writebuffer})==0) {
          $self->{tcpd}->{tcp}->{$fd}->{state}=9;
        } else {
          debug(sprintf("[%5d] Connection close pending, buffer size at %0d still. Can't close",$fd,$self->{tcpd}->{tcp}->{$fd}->{writebuffer}),5);
        }
      } elsif ($self->{tcpd}->{tcp}->{$fd}->{state}==9) {
        debug(sprintf("[%5d] Connection ready for closing (State %0d), closing socket.",$fd,$self->{tcpd}->{tcp}->{$fd}->{state}),5);
        $self->closesocket($handle);
      } else {
        if (($self->{tcpd}->{tcp}->{$fd}->{lasttime}+$self->{tcptimeout})<time()) { #Check time outs
          debug(sprintf("[%5d] TCP TIMEOUT %0dsec AT STATE %0d",$fd,$self->{tcptimeout},$self->{tcpd}->{tcp}->{$fd}->{state}),5);
          $self->closesocket($handle);
        }
      
      }
    }
  }
  $elapsed = tv_interval ( $t0, [gettimeofday]);
  if ($elapsed>$self->{jitterwarning}) {
    debug(sprintf("[%5d] PROCESS JITTER OF %.1f SECONDS",0,$elapsed),5);
  }
}

sub send { #Main writer - Put locks here if needed.
  my $self=shift;
  my $fd=shift;
  my $line=shift;
  $self->{tcpd}->{tcp}->{$fd}->{writefps}++;
  $self->{tcpd}->{tcp}->{$fd}->{writebuffer}.="$line".$self->{crlf};
}

sub send_raw { #This forces the packet thru !
  my $self=shift;
  my $fd=shift;
  my $line=shift;
  my $l=CORE::send($self->{tcpd}->{tcp}->{$fd}->{socket},$line,0);
}

sub clearbuffer {
  my $self=shift;
  my $fd=shift;
  $self->{tcpd}->{tcp}->{$fd}->{readbuffer}="";
}

sub opensocket { #Note that this completes a connection. Be it incoming or outgoing.
  my $self=shift;
  my $socket=shift;
  if ($socket) {
    my $fd=fileno $socket;
    fcntl($socket,F_SETFL,O_NONBLOCK);
    my $ip=$socket->peeraddr();
    my $port=$socket->peerport() || $socket->sockport() || 0 ;
    my $host="0.0.0.0";
    if ($ip) {
      $host=inet_ntoa($ip);
    }
    $self->{tcpd}->{selects}->add($socket);
    debug(sprintf("[%5d] %s Connection OPEN to %s:%d",$fd,$self->{tcpd}->{tcp}->{$fd}->{proto} || "Socket",$host,$port),5);
    $self->{tcpd}->{tcp}->{$fd}->{starttime}=[gettimeofday];
    $self->{tcpd}->{tcp}->{$fd}->{lasttime}=time();
    $self->{tcpd}->{tcp}->{$fd}->{parentfd}=0;
    $self->{tcpd}->{tcp}->{$fd}->{expiretime}=0;
    $self->{tcpd}->{tcp}->{$fd}->{socket}=$socket;
    $self->{tcpd}->{tcp}->{$fd}->{readbytes}=0;
    $self->{tcpd}->{tcp}->{$fd}->{writebytes}=0;
    $self->{tcpd}->{tcp}->{$fd}->{readbuffer}="";
    $self->{tcpd}->{tcp}->{$fd}->{writebuffer}="";
    $self->{tcpd}->{tcp}->{$fd}->{ratetime}=[gettimeofday];
    $self->{tcpd}->{tcp}->{$fd}->{readbps}=0;
    $self->{tcpd}->{tcp}->{$fd}->{writebps}=0;
    $self->{tcpd}->{tcp}->{$fd}->{readfps}=0;
    $self->{tcpd}->{tcp}->{$fd}->{writefps}=0;
    $self->{tcpd}->{tcp}->{$fd}->{clients}=0;
    $self->{tcpd}->{tcp}->{$fd}->{clientsps}=0;
    $self->{tcpd}->{tcp}->{$fd}->{hostname}=$host;
    $self->{tcpd}->{tcp}->{$fd}->{reason}="";
    $self->{tcpd}->{tcp}->{$fd}->{remote}=sprintf("%s:%0d",$host,$port);
    $self->{tcpd}->{tcp}->{$fd}->{auth}="";
    $self->{tcpd}->{tcp}->{$fd}->{type}=0; # 0 - fresh open, 1 - outwards, 2 - incoming/listening, 3 - udp, 4- raw tcp
    $self->{tcpd}->{tcp}->{$fd}->{state}=0; # 0 - fresh open, 1 - ready, 8 - request to close , 9 - ready to close, 10 - closed, waiting reo retry
    $self->{stats}->{$fd}->{remote}=sprintf("%s:%0d",$host,$port);
  } else {
    debug("[BUG] opensocket called without a socket !",3);
  }
}

sub end { #We have this when we wanna close by FD.
  my $self=shift;
  my $fd=shift;
  my $reason=shift || "(No reason)";
  if ($fd) {
    if (defined $self->{tcpd}->{tcp}->{$fd}->{state}) {
      if ($self->{tcpd}->{tcp}->{$fd}->{state}==8) {
        debug(sprintf("[%5d] Connection close pending actual closing. Already at state 8.",$fd),6);
      } elsif ($self->{tcpd}->{tcp}->{$fd}->{state}==9) {
        debug(sprintf("[%5d] Connection ready to close. Awaiting closesocket. At state 9",$fd),6);
      } else {
        debug(sprintf("[%5d] Closing connection - %s",$fd,$reason),5);
        $self->{tcpd}->{tcp}->{$fd}->{reason}=$reason;
        debug(sprintf("[%5d] Requesting to close connection (Set state from %0d to 8)",$fd,$self->{tcpd}->{tcp}->{$fd}->{state}),9);
        $self->{tcpd}->{tcp}->{$fd}->{state}=8;
      }
    } else {
      debug(sprintf("[%5d] Requesting end to a stateless connection.",$fd),3);
    }
  } else {
    debug("[BUG] end called without an FD !",2);
  }
}

sub closesocket {
  my $self=shift;
  my $socket=shift;
  my $fd=fileno $socket;
  if ($fd) { # Yes, it can disappear.. lol
    my $handler=$self->{tcpd}->{tcp}->{$fd}->{handler} || "default";
    if (defined $self->{handler}->{$handler}->{disconnect}) {
      $self->{handler}->{$handler}->{disconnect}($self,$fd,$self->{tcpd}->{tcp}->{$fd}->{reason});
    } else {
      $self->{handler}->{default}->{disconnect}($self,$fd,$self->{tcpd}->{tcp}->{$fd}->{reason});
    }
    if ((defined $self->{tcpd}->{tcp}->{$fd}->{readbytes}) && (defined $self->{tcpd}->{tcp}->{$fd}->{writebytes})) {
      my $rb_length=length $self->{tcpd}->{tcp}->{$fd}->{readbuffer};
      my $wb_length=length $self->{tcpd}->{tcp}->{$fd}->{writebuffer};
      my $elapsed=tv_interval ( $self->{tcpd}->{tcp}->{$fd}->{starttime}, [gettimeofday]) || 0.000001;
      debug(sprintf("[%5d] Connection CLOSED - Buffer Size of %dB / %dB",$fd,$rb_length,$wb_length),5);
      debug(sprintf("[%5d] Total Bytes Transfered %dB / %dB (at %dBps / %dBps)",$fd,$self->{tcpd}->{tcp}->{$fd}->{readbytes},$self->{tcpd}->{tcp}->{$fd}->{writebytes},$self->{tcpd}->{tcp}->{$fd}->{readbytes}/$elapsed,$self->{tcpd}->{tcp}->{$fd}->{writebytes}/$elapsed),6); 
    } else {
      debug(sprintf("[%5d] Connection REJECTED",$fd),5);
    }
    debug(sprintf("[%5d] Closing socket",$fd),4);
    delete $self->{tcpd}->{tcp}->{$fd}->{socket};
    delete $self->{tcpd}->{tcp}->{$fd}->{lasttime};
    delete $self->{tcpd}->{tcp}->{$fd}->{readbytes};
    delete $self->{tcpd}->{tcp}->{$fd}->{writebytes};
    delete $self->{tcpd}->{tcp}->{$fd}->{readbuffer};
    delete $self->{tcpd}->{tcp}->{$fd}->{writebuffer};
    delete $self->{tcpd}->{tcp}->{$fd}->{hostname};
    delete $self->{tcpd}->{tcp}->{$fd}->{state};
    delete $self->{tcpd}->{tcp}->{$fd}->{reason};
    delete $self->{tcpd}->{tcp}->{$fd}->{handler};
    delete $self->{tcpd}->{tcp}->{$fd}->{auth};
    delete $self->{tcpd}->{tcp}->{$fd};
    delete $self->{stats}->{$fd};
    $self->{tcpd}->{selects}->remove($socket); 
    close($socket);
  } else {
    my $handler= "default"; # Its a ghost !
    $self->{handler}->{default}->{disconnect}($self,0);
    debug(sprintf("[%5d] Connection Disappeared!",0),3);
    if ($socket) { #Just in case
      $self->{tcpd}->{selects}->remove($socket); 
      close($socket);
    }
  }
}

sub connect {
  my $self=shift;
  my $host=shift;
  my $port=shift;
  my $handler=shift || "default";
  my $localhost=shift;
  my $socket = IO::Socket::INET->new(
                    PeerHost => $host,
                     PeerPort => $port,
                     LocalAddr => $localhost,
                     Proto => 'tcp',   
                     ReuseAddr => 1,   
                     Blocking=>0,      
                    );
  if ($socket) {
    my $fd=fileno $socket;
    fcntl($socket,F_SETFL,O_NONBLOCK);
    $self->opensocket($socket);  
    $self->{tcpd}->{tcp}->{$fd}->{type}=1;  
    $self->{tcpd}->{tcp}->{$fd}->{parentfd}=0;
    $self->{tcpd}->{tcp}->{$fd}->{host}=$host;
    $self->{tcpd}->{tcp}->{$fd}->{port}=$port;
    $self->{tcpd}->{tcp}->{$fd}->{proto}='tcp';
    $self->{tcpd}->{tcp}->{$fd}->{handler}=$handler;
    debug(sprintf("[%5d] TCP Client connecting to %s:%d using handler '%s'",$fd,$host,$port,$handler),4);
    if (defined $self->{handler}->{$handler}->{connect})  {
      $self->{handler}->{$handler}->{connect}($self,$fd);
    } else {
      $self->{handler}->{default}->{connect}($self,$fd);
    }
  } else {
    debug(sprintf("[%5d] TCP Client failed to connect to %s:%s using handler '%s'",0,$host,$port,$handler),3);
  }
}  

sub connect_raw {
  my $self=shift;
  my $host=shift;
  my $port=shift;
  my $handler=shift || "default";
  my $localhost=shift;
  my $socket = IO::Socket::INET->new(
                    PeerHost => $host,
                     PeerPort => $port,
                     LocalAddr => $localhost,
                     Proto => 'tcp',   
                     ReuseAddr => 1,   
                     Blocking=>0,      
                    );
  if ($socket) {
    my $fd=fileno $socket;
    fcntl($socket,F_SETFL,O_NONBLOCK);
    $self->opensocket($socket);  
    $self->{tcpd}->{tcp}->{$fd}->{type}=4;  
    $self->{tcpd}->{tcp}->{$fd}->{parentfd}=0;
    $self->{tcpd}->{tcp}->{$fd}->{host}=$host;
    $self->{tcpd}->{tcp}->{$fd}->{port}=$port;
    $self->{tcpd}->{tcp}->{$fd}->{proto}='tcp';
    $self->{tcpd}->{tcp}->{$fd}->{handler}=$handler;
    debug(sprintf("[%5d] TCP Client connecting to %s:%d using handler '%s'",$fd,$host,$port,$handler),4);
    if (defined $self->{handler}->{$handler}->{connect})  {
      $self->{handler}->{$handler}->{connect}($self,$fd);
    } else {
      $self->{handler}->{default}->{connect}($self,$fd);
    }
  } else {
    debug(sprintf("[%5d] TCP Client failed to connect to %s:%s using handler '%s'",0,$host,$port,$handler),3);
  }
}  

sub connectudp {
  my $self=shift;
  my $host=shift;
  my $port=shift;
  my $handler=shift || "default";
  my $socket = IO::Socket::INET->new(
                    PeerHost => $host,
                     PeerPort => $port,
                     Proto => 'udp',   
                     ReuseAddr => 1,   
                     Blocking=>0,      
                    );
  if ($socket) {
    my $fd=fileno $socket;
    fcntl($socket,F_SETFL,O_NONBLOCK);
    $self->opensocket($socket);  
    $self->{tcpd}->{tcp}->{$fd}->{type}=1;  
    $self->{tcpd}->{tcp}->{$fd}->{parentfd}=0;
    $self->{tcpd}->{tcp}->{$fd}->{proto}='udp';
    $self->{tcpd}->{tcp}->{$fd}->{host}=$host;
    $self->{tcpd}->{tcp}->{$fd}->{port}=$port;
    $self->{tcpd}->{tcp}->{$fd}->{handler}=$handler;
    debug(sprintf("[%5d] UDP Client connecting to %s:%d using handler '%s'",$fd,$host,$port,$handler),4);
    if (defined $self->{handler}->{$handler}->{connect})  {
      $self->{handler}->{$handler}->{connect}($self,$fd);
    } else {
      $self->{handler}->{default}->{connect}($self,$fd);
    }
  } else {
    debug(sprintf("[%5d] UDP Client failed to connect to %s:%s using handler '%s'",0,$host,$port,$handler),3);
  }
}  

sub listen {
  my $self=shift;
  my $port=shift;
  my $handler=shift || "default";
  my $socket = IO::Socket::INET->new(
  #                         LocalHost => $LOCALHOST,
                           LocalPort => $port, 
                           Proto => 'tcp',
                           Listen => $self->{maxconnections},
                           ReuseAddr => 1,
                           Blocking=>0,   
                          );
  if ($socket) {
    fcntl($socket,F_SETFL,O_NONBLOCK);
    my $fd=fileno $socket;
    $self->opensocket($socket);
    $self->{tcpd}->{tcp}->{$fd}->{type}=2;
    $self->{tcpd}->{tcp}->{$fd}->{proto}='tcp';
    $self->{tcpd}->{tcp}->{$fd}->{handler}=$handler;
    debug(sprintf("[%5d] TCP Server started on 0.0.0.0:%d using handler '%s'",$fd,$port,$handler),4);
  } else {
    debug(sprintf("[%5d] TCP Server failed to start on 0.0.0.0:%d using handler '%s'",0,$port,$handler),3);
  }
}  

sub listenudp {
  my $self=shift;
  my $port=shift;
  my $handler=shift || "default";
  my $socket = IO::Socket::INET->new(
  #                         LocalHost => $LOCALHOST,
                           LocalPort => $port, 
                           Proto => 'udp',
#                           Listen => $self->{maxconnections},
                           ReuseAddr => 1,
                           Blocking=>0,   
                          );
  if ($socket) {
    fcntl($socket,F_SETFL,O_NONBLOCK);
    my $fd=fileno $socket;
    $self->opensocket($socket);
    $self->{tcpd}->{tcp}->{$fd}->{type}=3;
    $self->{tcpd}->{tcp}->{$fd}->{proto}='udp';
    $self->{tcpd}->{tcp}->{$fd}->{handler}=$handler;
    debug(sprintf("[%5d] UDP Server started on 0.0.0.0:%d using handler '%s'",$fd,$port,$handler),4);
  } else {
    debug(sprintf("[%5d] UDP Server failed to start on 0.0.0.0:%d using handler '%s' - %s",0,$port,$handler,$!),3);
  }
}  

sub stop {
  my $self=shift;
  foreach my $handle ($self->{tcpd}->{selects}->handles()) {
    if ($handle) {
      $self->closesocket($handle);
    }
  }
}

### Connection information abstraction layer

sub host {
  my $self=shift;
  my $fd=shift;
  return $self->{tcpd}->{tcp}->{$fd}->{hostname} || "";
}

sub connectioncount {
  my $self=shift;
  my $count=0;
  foreach my $handle ($self->{tcpd}->{selects}->handles()) {
    my $tfd=fileno $handle;
    $count++;
  }    
  return $count;
}


sub clientcount {
  my $self=shift;
  my $count=0;
  foreach my $handle ($self->{tcpd}->{selects}->handles()) {
    my $tfd=fileno $handle;
    if ($self->{tcpd}->{tcp}->{$tfd}->{type}!=2) {
      $count++;
    }
  }    
  return $count;
}

sub writecount {
  my $self=shift;
  my $count=0;
  foreach my $handle ($self->{tcpd}->{selects}->handles()) {
    my $fd=fileno $handle;
    if ($self->{tcpd}->{tcp}->{$fd}->{type}==2) {
#      debug(sprintf("[%5d] Cant Write to Master Socket",$fd),3);
    } else {
      if ($self->{tcpd}->{tcp}->{$fd}->{writebuffer}) {
        $count++;
      }
    }
  }
  return $count;
}


sub getFD {
  open P,"/proc/$$/limits";
  while (<P>) {
    if (/Max open files\s+(\d+)\s+(\d+)/i) {
      close P;    
      return $2;
    }
  }
  close P;
  return 0;
}

sub updateStats {
  my $self=shift;
  $self->{stats}->{timestamp}=time();
  $self->{stats}->{datetime}=apachedatetime($self->{stats}->{timestamp});
  $self->{scoreboard}->{timestamp}=time();
  $self->{scoreboard}->{datetime}=apachedatetime($self->{stats}->{timestamp});
  $self->{scoreboard}->{clients}=0;
  $self->{scoreboard}->{servers}=0;
  foreach my $handle ($self->{tcpd}->{selects}->handles()) {
    my $fd=fileno $handle;
    my $elapsed=tv_interval($self->{tcpd}->{tcp}->{$fd}->{ratetime}, [gettimeofday]);
    if ($elapsed>60) {
      $self->{stats}->{$fd}->{readbps}=$self->{tcpd}->{tcp}->{$fd}->{readbps}/$elapsed;
      $self->{stats}->{$fd}->{writebps}=$self->{tcpd}->{tcp}->{$fd}->{writebps}/$elapsed;
      $self->{stats}->{$fd}->{readfps}=$self->{tcpd}->{tcp}->{$fd}->{readfps}/$elapsed;
      $self->{stats}->{$fd}->{writefps}=$self->{tcpd}->{tcp}->{$fd}->{writefps}/$elapsed;
      $self->{stats}->{$fd}->{clientsps}=$self->{tcpd}->{tcp}->{$fd}->{clientsps}/$elapsed;
      $self->{stats}->{$fd}->{lastupdate}=time();
      $self->{tcpd}->{tcp}->{$fd}->{ratetime}=[gettimeofday];
      $self->{tcpd}->{tcp}->{$fd}->{readbps}=0;
      $self->{tcpd}->{tcp}->{$fd}->{writebps}=0;
      $self->{tcpd}->{tcp}->{$fd}->{readfps}=0;
      $self->{tcpd}->{tcp}->{$fd}->{writefps}=0;      
      $self->{tcpd}->{tcp}->{$fd}->{clientsps}=0;      
    } 
    $self->{stats}->{$fd}->{readbytes}=$self->{tcpd}->{tcp}->{$fd}->{readbytes};
    $self->{stats}->{$fd}->{writebytes}=$self->{tcpd}->{tcp}->{$fd}->{writebytes};
    $self->{stats}->{$fd}->{age}=sprintf("%.1f",tv_interval($self->{tcpd}->{tcp}->{$fd}->{starttime}));

    if ($self->{tcpd}->{tcp}->{$fd}->{type}==2) {
      my $count=0;
      foreach my $handle ($self->{tcpd}->{selects}->handles()) {
        my $tfd=fileno $handle;
        if ($self->{tcpd}->{tcp}->{$tfd}->{parentfd}==$fd) {
          $count++;
        }
      }    
      $self->{stats}->{$fd}->{connected}=$count;
      $self->{scoreboard}->{$self->{tcpd}->{tcp}->{$fd}->{remote}}->{clients}=$count;
      $self->{scoreboard}->{$self->{tcpd}->{tcp}->{$fd}->{remote}}->{totalclients}=$self->{tcpd}->{tcp}->{$fd}->{clients};
      $self->{scoreboard}->{$self->{tcpd}->{tcp}->{$fd}->{remote}}->{connectrate}=$self->{stats}->{$fd}->{clientsps};
      $self->{scoreboard}->{$self->{tcpd}->{tcp}->{$fd}->{remote}}->{readbps}=$self->{stats}->{$fd}->{readbps};
      $self->{scoreboard}->{$self->{tcpd}->{tcp}->{$fd}->{remote}}->{writebps}=$self->{stats}->{$fd}->{writebps};
      $self->{scoreboard}->{$self->{tcpd}->{tcp}->{$fd}->{remote}}->{readbytes}=$self->{stats}->{$fd}->{readbytes};
      $self->{scoreboard}->{$self->{tcpd}->{tcp}->{$fd}->{remote}}->{writebytes}=$self->{stats}->{$fd}->{writebytes};
      $self->{scoreboard}->{servers}++;
    } else {
      $self->{scoreboard}->{clients}++;
    }
  }
}



#######################################################################
## DO NOT EDIT ANY PROCEDURES ABOVE THIS LINE. ONLY EDIT THOSE BELOW ##
#######################################################################

sub _funcaccept { #This routine is called whenever a TCP connection is accepted by server
  my $self=shift;
  my $fd=shift;
  $self->{tcpd}->{tcp}->{$fd}->{state}=1;
  debug(sprintf("[%5d] Default Accept Processor",$fd),7);
#  $self->send($fd,"HTTP/1.0 200 OK");
#  $self->send($fd,"Server: TCPD");
#  $self->send($fd,"");
#  $self->send($fd,"<html>Hello World</html>");
#  $self->{tcpd}->{tcp}->{$fd}->{state}=8;
#  $self->end($fd);        
}

sub _funcconnect { #This routine is called whenever a TCP connection is connected outgoing
  my $self=shift;
  my $fd=shift;
  debug(sprintf("[%5d] Default Connect Processor",$fd),7);
}
sub _funcdisconnect { #This routine is called whenever a TCP connection is disconnected 
  my $self=shift;
  my $fd=shift;
  my $reason=shift || "";
  debug(sprintf("[%5d] Default Disconnect Processor. Reason - %s",$fd,$reason),7);
}

sub _funcline { # Main line processor. Called with file descriptor and line received.
  my $self=shift;
  my $fd=shift;
  my $line=shift;
  debug(sprintf("[%5d] Default Line Processsor '%s'",$fd,$line),7);
#  $self->send($fd,$line);
}

sub _funcraw { # Main raw processor. Called with file descriptor and line received.
  my $self=shift;
  my $fd=shift;
  my $line=shift;
  debug(sprintf("[%5d] Default Raw Processsor '%s'",$fd,$line),7);
#  $self->send($fd,$line);
}

sub _funcline_httpd { # Main line processor. Called with file descriptor and line received.
  my $self=shift;
  my $fd=shift;
  my $line=shift;
  debug(sprintf("[%5d] Process '%s'",$fd,$line),7);
  if ($line eq "\r") {
    $self->send($fd,"HTTP/1.0 200 OK");
    $self->send($fd,"Server: TCPD");
    $self->send($fd,"");
    $self->send($fd,"<html>Hello World</html>");
    $self->end($fd);        
  }
}


1;
