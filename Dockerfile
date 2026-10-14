# Wurd server: PHP 8.5 + Apache, running as www-data on port 8026 with a read-only root filesystem.
# Writable state lives in the /data volume only.
FROM php:8.5-apache@sha256:974e3a920309308e1690ed607e6cc3061d6906f90cc8d30fe519daa48bccf101

# Only the Apache pieces Wurd uses: no autoindex, status page, CGI or default site
RUN a2enmod headers remoteip \
 && a2dismod -f autoindex status negotiation \
 && a2disconf docker-php other-vhosts-access-log serve-cgi-bin localized-error-pages \
 && a2dissite 000-default \
 && echo '# Listen is set in sites-enabled/wurd.conf' > /etc/apache2/ports.conf \
 && mkdir -p /data /srv/wurd \
 && chown www-data:www-data /data \
 && chmod 0700 /data

COPY docker/php.ini "$PHP_INI_DIR/conf.d/zz-wurd.ini"
COPY docker/apache.conf /etc/apache2/sites-enabled/wurd.conf
COPY --chmod=0755 docker/entrypoint.sh /usr/local/bin/wurd-entrypoint
COPY bin/ /app/bin/
COPY public/ /app/public/
COPY src/ /app/src/

# Apache's runtime files go to /tmp, the only other writable place (a tmpfs in compose.yaml)
ENV APACHE_RUN_DIR=/tmp/apache2 \
    APACHE_LOCK_DIR=/tmp/apache2 \
    APACHE_PID_FILE=/tmp/apache2/apache2.pid

USER www-data
EXPOSE 8026
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s \
  CMD curl -fsS -o /dev/null http://127.0.0.1:8026/api/health || exit 1
ENTRYPOINT ["wurd-entrypoint"]
