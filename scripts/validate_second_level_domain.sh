#!/bin/bash
set -e

if [ "$#" -ne 4 ]; then
  echo "Usage: validate_second_level_domain.sh domain_name record_type dir_to_save_answers ns_server"
  echo "Example: validate_second_level_domain.sh metebalci.com A /tmp 8.8.8.8"
  exit 1
fi

IFS='.' read domain2 domain1 <<< $1
rr=$2
dest=$3
server=$4

echo "testing $domain2.$domain1 $rr using $server"
echo ""

# save $rr and all DNSKEY and DS records
echo "downlading answers"

echo "downloading $domain2.$domain1 $rr"
digsec query @$server $domain2.$domain1 $rr +rd +do +udp_payload_size=2048 +save-answer +save-answer-dir=$dest
echo "downloading $domain2.$domain1 DNSKEY"
digsec query @$server $domain2.$domain1 DNSKEY +rd +do +udp_payload_size=2048 +save-answer +save-answer-dir=$dest
echo "downloading $domain2.$domain1 DS"
digsec query @$server $domain2.$domain1 DS +rd +do +udp_payload_size=2048 +save-answer +save-answer-dir=$dest

echo "downloading $domain1 DNSKEY"
digsec query @$server $domain1 DNSKEY +rd +do +udp_payload_size=2048 +save-answer +save-answer-dir=$dest
echo "downloading $domain1 DS"
digsec query @$server $domain1 DS +rd +do +udp_payload_size=2048 +save-answer +save-answer-dir=$dest

echo "downloading . DNSKEY"
digsec query @$server . DNSKEY +rd +do +udp_payload_size=2048 +save-answer +save-answer-dir=$dest

# download trust anchors

echo "downloading . DS (trust anchor)"
digsec download +save-ds-anchors=$dest/_root.IN

# validate
echo ""
echo "validating answers"

echo "validating $domain2.$domain1 $rr with $domain2.$domain1 DNSKEY"
digsec validate $dest/$domain2.$domain1.IN.$rr $dest/$domain2.$domain1.IN.RRSIG.$rr $dest/$domain2.$domain1.IN.DNSKEY
echo "validating $domain2.$domain1 DNSKEY with $domain2.$domain1 DS"
digsec validate $dest/$domain2.$domain1.IN.DNSKEY $dest/$domain2.$domain1.IN.RRSIG.DNSKEY $dest/$domain2.$domain1.IN.DS
echo "validating $domain2.$domain1 DS with $domain1 DNSKEY"
digsec validate $dest/$domain2.$domain1.IN.DS $dest/$domain2.$domain1.IN.RRSIG.DS $dest/$domain1.IN.DNSKEY

echo "validating $domain1 DNSKEY with $domain1 DS"
digsec validate $dest/$domain1.IN.DNSKEY $dest/$domain1.IN.RRSIG.DNSKEY $dest/$domain1.IN.DS
echo "validating $domain1 DS with . DNSKEY"
digsec validate $dest/$domain1.IN.DS $dest/$domain1.IN.RRSIG.DS $dest/_root.IN.DNSKEY

echo "validating . DNSKEY with . DS (trust anchor)"
digsec validate $dest/_root.IN.DNSKEY $dest/_root.IN.RRSIG.DNSKEY $dest/_root.IN.DS
