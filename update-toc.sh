#!/bin/bash

#
# This script updates the table of content (ToC) in the README.md
#

cd $(dirname "$0")

if which markdown-github-toc > /dev/null; then
  # Copy markdown to README.md and add Table of Content
  markdown-github-toc README.md --maxdepth 3 --insert
else
  echo "You need to install markdown-utilities through NPM, run:"
  echo ""
  echo "npm install -g markdown-utilities"
  echo ""
  exit 1
fi
