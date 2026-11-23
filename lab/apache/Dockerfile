# Apache httpd 2.4.49 made exploitable for CVE-2021-41773, as vulhub does: the version
# alone is vulnerable, but with httpd's default configuration the path traversal is
# denied. Granting the root directory makes it a file read (LFI); enabling CGI makes it
# command execution. Lab use only, on an isolated network.
#
# The difference matters: on the default image, nuclei's template does NOT confirm the
# CVE (ReconKit keeps the version match as "firm"); on this one it does ("confirmed").
FROM httpd:2.4.49@sha256:dcba0d12e2362fb0c50ec524ae8aa1cca4a4ba7216617a57e7bbca20767e79cc
RUN conf=/usr/local/apache2/conf/httpd.conf \
 && sed -i \
      -e 's/^\([[:space:]]*\)#LoadModule cgid_module /\1LoadModule cgid_module /' \
      -e '/^<Directory \/>/,/^<\/Directory>/ s/Require all denied/Require all granted/' \
      "$conf" \
 && grep -Eq '^[[:space:]]*LoadModule cgid_module ' "$conf" \
 && sed -n '/^<Directory \/>/,/^<\/Directory>/p' "$conf" | grep -q 'Require all granted'
