FROM nginx:1.28-alpine
COPY deploy/nginx.conf /etc/nginx/nginx.conf
USER nginx
EXPOSE 3000
ENTRYPOINT ["nginx"]
CMD ["-g", "daemon off;"]
