#!/bin/sh
SV=$2
line=$(head -n 1 $1)

sed -e 1d $1 | sort -t, -k $SV -n |sed -e "1i$line" > char_sort.csv
cut -d"," -f$2 char_sort.csv | sed -e 1d | uniq -c | awk 'BEGIN {OFS=","} { print $2 "," $1}' | awk -F, '{$3=c+=$2}1' | awk 'BEGIN {FS=" "} { print $1 "," $2 "," $3}' | sort -t, -k2 -nr | cat -n | sed -e 's/\s\+/,/g' | sed '/^,/ s/.//'| sed -e '1i\rank,attribute,freq,cum' > char_cum.csv