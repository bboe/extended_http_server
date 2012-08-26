#!/bin/bash

module=ext_http_server.py


# pep8
output=$(pep8 $module)
if [ -n "$output" ]; then
    echo "---pep8---"
    echo -e "$output"
    exit 1
fi

# pylint
output=$(pylint $module 2> /dev/null)
if [ -n "$output" ]; then
    echo "--pylint--"
    echo -e "$output"
fi

echo "---pyflakes---"
pyflakes  $module

exit 0