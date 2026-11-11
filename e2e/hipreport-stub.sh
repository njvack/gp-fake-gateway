#!/bin/sh
# Minimal --csd-wrapper for e2e tests: prints a tiny, valid HIP report.
md5=
while [ $# -gt 0 ]; do
  case "$1" in
    --md5) md5=$2; shift ;;
  esac
  shift
done
cat <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<hip-report name="hip-report">
<md5-sum>$md5</md5-sum>
<user-name>test</user-name>
<hip-report-version>4</hip-report-version>
<categories/>
</hip-report>
EOF
