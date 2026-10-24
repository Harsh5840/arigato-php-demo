# INTENTIONALLY AFFECTED DEMO BASELINE. Do not deploy this image.
FROM php:8.3.36-cli-bookworm@sha256:cdb77e306d6bb99db40e513fbe036ecc6c53b575cbcb7e581387845fef26d755

WORKDIR /app
COPY config/security.ini /usr/local/etc/php/conf.d/zz-sakurashop.ini
COPY src/ ./src/
COPY public/ ./public/
USER 10001:10001
EXPOSE 8080
CMD ["php", "-S", "0.0.0.0:8080", "-t", "public", "public/index.php"]
