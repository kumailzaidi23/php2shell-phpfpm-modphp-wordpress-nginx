FROM php:8.4.26-apache@sha256:60111400ff77bdc44fa79b4f072afe49a42abba71e0846ad496be4761dc9c11a

ARG WORDPRESS_URL=https://wordpress.org/wordpress-7.0.7.tar.gz
ARG WORDPRESS_SHA256=e4f12b690853e4cf65aa674d018536d5c46a58698313c5997ca0c5d2c6b8ba0d
ARG LOCAL_FLAG=hitcon{local_apache84_dummy_do_not_submit}

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && docker-php-ext-install -j2 mysqli pdo_mysql \
    && cp /usr/local/etc/php/php.ini-production /usr/local/etc/php/php.ini \
    && curl -fsSL "$WORDPRESS_URL" -o /tmp/wordpress.tar.gz \
    && echo "$WORDPRESS_SHA256  /tmp/wordpress.tar.gz" | sha256sum -c - \
    && tar -xzf /tmp/wordpress.tar.gz -C /var/www/html --strip-components=1 \
    && rm /tmp/wordpress.tar.gz \
    && rm -rf /var/lib/apt/lists/* \
    && chown -R www-data:www-data /var/www/html

COPY wp-config.php /var/www/html/wp-config.php

RUN chown www-data:www-data /var/www/html/wp-config.php \
    && mkdir -p /out \
    && chown www-data:www-data /out \
    && printf '%s\n' "$LOCAL_FLAG" > /flag \
    && chmod 0444 /flag
