# INTENTIONALLY AFFECTED DEMO BASELINE. Do not deploy this image.
FROM php:8.3.35-cli-bookworm

WORKDIR /app
COPY config/security.ini /usr/local/etc/php/conf.d/zz-sakurashop.ini
COPY src/ ./src/
COPY public/ ./public/
USER 10001:10001
EXPOSE 8080
CMD ["php", "-S", "0.0.0.0:8080", "-t", "public", "public/index.php"]
