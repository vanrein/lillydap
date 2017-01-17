# This script is not necessary if you use the .bin directly.
# If you intend to run it, be sure to have "hexin" in your path.
# You will find hexin included in https://github.com/vanrein/hexio

# PATH="$PATH:/usr/local/src/hexio"

for f in *.hex
do
	echo Mapping $f to ${f%.hex}.bin
	cut -c 8- $f | hexin > ${f%.hex}.bin
	echo
done

