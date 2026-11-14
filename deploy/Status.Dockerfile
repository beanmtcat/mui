FROM node:22.18.0-bookworm AS status-builder
WORKDIR /src/status-web
COPY status-web/package.json status-web/package-lock.json status-web/tsconfig.json status-web/vite.config.ts status-web/index.html ./
RUN npm ci --no-fund
COPY status-web/scripts ./scripts
COPY status-web/src ./src
RUN npm run build

FROM nginx:stable-alpine
ENV MUI_STATUS_BACKEND_URL=http://mui-service:8088 \
    MUI_DNS_RESOLVER=127.0.0.11 \
    MUI_EDGE_PROXY_CIDR=127.0.0.1/32 \
    NGINX_ENVSUBST_FILTER=^MUI_
RUN apk add --no-cache ca-certificates
COPY --from=status-builder /src/status-web/dist /usr/share/nginx/html
COPY deploy/nginx/status.conf.template /etc/nginx/templates/default.conf.template
EXPOSE 8089
