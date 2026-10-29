# PHP2Shell lab: PHP 8.2.34 (last release before the CVE-2026-109618/109619 fix in 8.2.x)
# Apache + mod_php (prefork) - the SAPI with confirmed RCE for both CVEs.
# LAB ONLY: intentionally vulnerable. Bind to 127.0.0.1, never expose publicly.
FROM php:8.2.34-apache

COPY php2shell.ini /usr/local/etc/php/conf.d/zz-php2shell.ini
COPY apache.conf /etc/apache2/conf-enabled/zz-php2shell.conf
COPY index.php /var/www/html/index.php
COPY info.php /var/www/html/info.php
RUN chown -R www-data:www-data /var/www/html

EXPOSE 80
