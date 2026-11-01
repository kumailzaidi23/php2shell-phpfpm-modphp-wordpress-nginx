FROM php:8.3.35-apache@sha256:c59c808172ee3672cd334f8f2a5d7b1480a9d7273a368f412b8ee9b4ef418184

ARG WORDPRESS_URL=https://wordpress.org/wordpress-7.1.3.tar.gz
ARG WORDPRESS_SHA256=d2a09acb6a15e3b9c471d72557753c266d6f41a79ed19bfe04cbfe49e283b2a5
ARG LOCAL_FLAG=hitcon{local_apache83_instance_do_not_submit}

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

COPY lab/apache/wp-config.php /var/www/html/wp-config.php
COPY profiles/apache83/apache-one.conf /etc/apache2/conf-enabled/zz-php2shell-one-worker.conf

RUN chown www-data:www-data /var/www/html/wp-config.php \
    && mkdir -p /out \
    && chown www-data:www-data /out \
    && printf '%s\n' "$LOCAL_FLAG" > /flag \
    && chmod 0444 /flag
