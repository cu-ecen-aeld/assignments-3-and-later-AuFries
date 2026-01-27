#!/bin/sh
# Provides the number of files and lines that match a particular string
# Parameters:
# filesdir - the directory to search
# searchstr - the string to search
# Exits with value 1 error if parameters note specified or if filesdir does not exist

# Check if the number of params is correct
if [ "$#" -ne 2 ]; then
    echo "Incorrect number of arguments. $# provided. 2 required"
    exit 1
fi

FILES_DIR=$1
SEARCH_STR=$2
# Ensure that filesdir exists
if [ ! -d "$FILES_DIR" ]; then
    echo "Directory does not exist: $FILES_DIR"
    exit 1
fi

num_files=$( find "$FILES_DIR" -type f -exec grep -l "$SEARCH_STR" {} \; | wc -l )
num_lines=$( grep -r "$SEARCH_STR" "$FILES_DIR" | wc -l )

echo "The number of files are $num_files and the number of matching lines are $num_lines"