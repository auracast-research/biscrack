ts=`date +%s`
grep -e "^PDU [0-9]*,[0-9]\{2,10\}" $1 | head -n 1 | sed 's/PDU //' | cut -d ',' -f 3 | xxd -p -r > pdu_$ts.bin
counter=`grep -o -e "^PDU [0-9]*,[0-9]\{2,10\}" $1 | head -n 1 | cut -d "," -f 1 | grep -o "[0-9]\{2,10\}$"`
grep -e "^BIGInfo [0-9]" $1 | head -n 1 | sed 's/BIGInfo //' | cut -d ',' -f 2 | xxd -p -r > biginfo_$ts.bin
echo ""
echo "./biscrack -m wordlist -w rockyou.txt -b biginfo_$ts.bin -p pdu_$ts.bin -c $counter" -t 12
