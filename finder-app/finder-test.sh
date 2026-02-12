#!/bin/sh
PATH=$PATH:/bin/finder-app
# Tester script for assignment 1 and assignment 2
# Author: Siddhant Jajoo

set -e
set -u

NUMFILES=10
WRITESTR=AELD_IS_FUN
WRITEDIR=/tmp/aeld-data

# Determine script directory and config directory. Default config dir is
# /etc/finder-app/conf to allow running this script from /usr/bin. Change by setting FINDER_APP_CONF
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CONF_DIR="/etc/finder-app/conf"
if [ -n "${FINDER_APP_CONF:-}" ]; then
	CONF_DIR="$FINDER_APP_CONF"
fi
if [ ! -d "$CONF_DIR" ]; then
	if [ -d "$SCRIPT_DIR/conf" ]; then
		CONF_DIR="$SCRIPT_DIR/conf"
	else
		echo "Config directory not found at $CONF_DIR or $SCRIPT_DIR/conf" >&2
		exit 1
	fi
fi

username=$(cat "$CONF_DIR/username.txt")

if [ $# -lt 3 ]
then
	echo "Using default value ${WRITESTR} for string to write"
	if [ $# -lt 1 ]
	then
		echo "Using default value ${NUMFILES} for number of files to write"
	else
		NUMFILES=$1
	fi	
else
	NUMFILES=$1
	WRITESTR=$2
	WRITEDIR=/tmp/aeld-data/$3
fi

MATCHSTR="The number of files are ${NUMFILES} and the number of matching lines are ${NUMFILES}"

echo "Writing ${NUMFILES} files containing string ${WRITESTR} to ${WRITEDIR}"

rm -rf "${WRITEDIR}"

# create $WRITEDIR if not assignment1
assignment=$(cat "$CONF_DIR/assignment.txt") # modified from ../conf/assignment.txt for assignment 3 part

if [ $assignment != 'assignment1' ]
then
	mkdir -p "$WRITEDIR"

	#The WRITEDIR is in quotes because if the directory path consists of spaces, then variable substitution will consider it as multiple argument.
	#The quotes signify that the entire string in WRITEDIR is a single string.
	#This issue can also be resolved by using double square brackets i.e [[ ]] instead of using quotes.
	if [ -d "$WRITEDIR" ]
	then
		echo "$WRITEDIR created"
	else
		exit 1
	fi
fi
#echo "Removing the old writer utility and compiling as a native application"
# make clean TODO: assignment 3 part 2 use cross-compiler
# make

for i in $( seq 1 $NUMFILES)
do
	if ! command -v writer >/dev/null 2>&1; then
		echo "writer executable not found in PATH" >&2
		exit 1
	fi
	writer "$WRITEDIR/${username}$i.txt" "$WRITESTR"
done


pwd

if ! command -v finder.sh >/dev/null 2>&1; then
	echo "finder.sh executable not found in PATH" >&2
	exit 1
fi

OUTPUTSTRING=$(finder.sh "$WRITEDIR" "$WRITESTR")

# Save the output for assignment 4 verification
echo "$OUTPUTSTRING" > /tmp/assignment4-result.txt

# remove temporary directories
rm -rf /tmp/aeld-data

set +e
echo ${OUTPUTSTRING} | grep "${MATCHSTR}"
if [ $? -eq 0 ]; then
	echo "success"
	exit 0
else
	echo "failed: expected  ${MATCHSTR} in ${OUTPUTSTRING} but instead found"
	exit 1
fi
