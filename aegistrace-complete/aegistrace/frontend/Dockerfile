FROM nginx:1.28-alpine
COPY deploy/nginx.conf /etc/nginx/nginx.conf.template
COPY frontend/entrypoint.sh /usr/local/bin/frontend-entrypoint.sh
RUN chmod 0555 /usr/local/bin/frontend-entrypoint.sh
USER nginx
EXPOSE 3000
ENTRYPOINT ["/usr/local/bin/frontend-entrypoint.sh"]
