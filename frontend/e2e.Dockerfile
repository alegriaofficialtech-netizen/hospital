FROM node:22-bookworm-slim
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY . .
RUN npx playwright install --with-deps chromium
ENV CI=1
CMD ["npx", "playwright", "test", "--config", "playwright.config.ts"]
