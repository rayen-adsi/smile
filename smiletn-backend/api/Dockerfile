FROM node:20-alpine

WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm ci --omit=dev

COPY src ./src

# data dir for uploads (mounted as volume by compose)
RUN mkdir -p /data/uploads && chown -R node:node /data/uploads
ENV UPLOAD_DIR=/data/uploads

USER node
EXPOSE 3000
CMD ["node", "src/server.js"]
