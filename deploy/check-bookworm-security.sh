#!/bin/sh
# Check Debian package revisions, including backported security fixes.
set -eu

require_version() {
    installed=$(dpkg-query -W -f='${db:Status-Status} ${Version}' "$1")
    if [ "${installed%% *}" != installed ] || ! dpkg --compare-versions "${installed#* }" ge "$2"; then
        printf '%s requires Debian version %s or newer (found %s)\n' "$1" "$2" "$installed" >&2
        exit 1
    fi
}

require_version libbrotli1 1.0.9-2+deb12u1             # DLA-4855-1
require_version libexpat1 2.5.0-1+deb12u5              # DLA-4849-1
require_version libssl3 3.0.22-1~deb12u2               # DLA-4859-1
require_version openssl 3.0.22-1~deb12u2
require_version apt 2.6.2                              # DLA-4880-1
require_version libapt-pkg6.0 2.6.2
require_version ca-certificates 20250419~deb12u2       # DLA-4845-1
require_version libsasl2-2 2.1.28+dfsg-10+deb12u1      # DLA-4871-1
require_version libsasl2-modules-db 2.1.28+dfsg-10+deb12u1
