FROM nginx:alpine

RUN apk add --no-cache gettext

COPY . /usr/share/nginx/html
COPY docker/nginx.conf /etc/nginx/conf.d/default.conf
COPY docker/inject-config.sh /docker-entrypoint.d/99-inject-config.sh
RUN chmod +x /docker-entrypoint.d/99-inject-config.sh

EXPOSE 8080
