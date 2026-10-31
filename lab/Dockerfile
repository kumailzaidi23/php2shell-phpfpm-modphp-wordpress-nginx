FROM php:8.5.11-fpm-alpine@sha256:fa01fb1645cd0fc566a5f146b099adace33b906571f972f71f2182a7c12d1cd7

ARG WORDPRESS_URL=https://wordpress.org/wordpress-6.9.10.tar.gz
ARG WORDPRESS_SHA256=a1c0dc12e2271c6afaabf329d5af7a976f8d2c8c592773178a5baaeafc2d4f4a

RUN apk add --no-cache musl=1.2.6-r3 curl \
    && apk add --no-cache --virtual .phpize-deps $PHPIZE_DEPS \
    && docker-php-ext-install -j2 mysqli pdo_mysql \
    && apk del .phpize-deps \
    && curl -fsSL "$WORDPRESS_URL" -o /tmp/wordpress.tar.gz \
    && echo "$WORDPRESS_SHA256  /tmp/wordpress.tar.gz" | sha256sum -c - \
    && tar -xzf /tmp/wordpress.tar.gz -C /var/www/html --strip-components=1 \
    && rm /tmp/wordpress.tar.gz \
    && chown -R www-data:www-data /var/www/html

COPY wp-config.php /var/www/html/wp-config.php
COPY fpm.conf /usr/local/etc/php-fpm.d/zz-local-research.conf
COPY php.ini /usr/local/etc/php/conf.d/zz-local-research.ini

ARG LOCAL_FLAG=hitcon{local_fpm85_dummy_do_not_submit}
RUN chown www-data:www-data /var/www/html/wp-config.php \
    && printf '%s\n' "$LOCAL_FLAG" > /flag \
    && chmod 0444 /flag
