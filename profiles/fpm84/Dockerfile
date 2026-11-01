FROM php:8.4.26-fpm-alpine3.23@sha256:b2a757dc9d3c05a6a97c05cacd26b981b6225e65cc78da6ccb2ea0a8b4b6196b

ARG WORDPRESS_URL=https://wordpress.org/wordpress-6.9.10.tar.gz
ARG WORDPRESS_SHA256=a1c0dc12e2271c6afaabf329d5af7a976f8d2c8c592773178a5baaeafc2d4f4a

RUN apk add --no-cache --virtual .phpize-deps $PHPIZE_DEPS \
    && docker-php-ext-install -j2 mysqli pdo_mysql \
    && apk del .phpize-deps \
    && wget -qO /tmp/wordpress.tar.gz "$WORDPRESS_URL" \
    && echo "$WORDPRESS_SHA256  /tmp/wordpress.tar.gz" | sha256sum -c - \
    && tar -xzf /tmp/wordpress.tar.gz -C /var/www/html --strip-components=1 \
    && rm /tmp/wordpress.tar.gz \
    && chown -R www-data:www-data /var/www/html

COPY lab/wp-config.php /var/www/html/wp-config.php
COPY lab/fpm.conf /usr/local/etc/php-fpm.d/zz-local-research.conf
COPY lab/php.ini /usr/local/etc/php/conf.d/zz-local-research.ini

ARG LOCAL_FLAG=hitcon{local_fpm84_dummy_do_not_submit}
RUN chown www-data:www-data /var/www/html/wp-config.php \
    && printf '%s\n' "$LOCAL_FLAG" > /flag \
    && chmod 0444 /flag
