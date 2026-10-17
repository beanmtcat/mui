FROM node:22.18.0-bookworm AS web-builder
WORKDIR /src/web
COPY web/package.json web/package-lock.json web/tsconfig.json web/vite.config.ts web/index.html ./
RUN npm ci --no-fund
COPY web/src ./src
RUN npm run build

FROM nginx:stable-alpine
ENV MUI_BACKEND_URL=http://mui-service:8087 \
    MUI_DNS_RESOLVER=127.0.0.11 \
    MUI_EDGE_PROXY_CIDR=127.0.0.1/32 \
    NGINX_ENVSUBST_FILTER=^MUI_
RUN apk add --no-cache ca-certificates
COPY --from=web-builder /src/web/dist /usr/share/nginx/html
COPY deploy/nginx/default.conf.template /etc/nginx/templates/default.conf.template
COPY deploy/nginx/routes.conf /etc/nginx/mui/routes.conf
EXPOSE 8086
