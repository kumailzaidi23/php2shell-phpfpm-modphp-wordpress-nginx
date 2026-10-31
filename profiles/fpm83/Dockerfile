FROM php:8.3.35-fpm-alpine@sha256:454b11c8907e32878ce92e87b13c14e1bbe6e1b10f4f96d4a19c9b62ec675d41

ARG WORDPRESS_URL=https://wordpress.org/wordpress-7.1.3.tar.gz
ARG WORDPRESS_SHA256=d2a09acb6a15e3b9c471d72557753c266d6f41a79ed19bfe04cbfe49e283b2a5

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

ARG LOCAL_FLAG=hitcon{local_fpm83_dummy_do_not_submit}
RUN chown www-data:www-data /var/www/html/wp-config.php \
    && printf '%s\n' "$LOCAL_FLAG" > /flag \
    && chmod 0444 /flag
