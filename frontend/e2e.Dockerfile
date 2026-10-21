# E2E runner image for the F11 real stack.
#
# Derived from the official Playwright image on purpose. The previous version
# started from node:22-bookworm-slim and ran `playwright install --with-deps
# chromium`, which triggers an apt install plus a browser download and
# extraction on the host. On this laptop-class package that drove the CPU to
# 93 C and aborted Stage B2 twice, at two cores and again at one.
#
# The base image already ships the browsers and every system dependency, so the
# work left here is a small test-runner install and two COPY layers.
#
# PLAYWRIGHT_VERSION must equal @playwright/test in package-lock.json:
# playwright-core pins the exact browser build revision shipped in the image,
# so a mismatch only fails at runtime. build-images.sh reads the version from
# the lock; the default below is a fallback for a standalone build.
ARG PLAYWRIGHT_VERSION=1.64.1
FROM mcr.microsoft.com/playwright:v${PLAYWRIGHT_VERSION}-noble

ARG PLAYWRIGHT_VERSION=1.64.1
WORKDIR /app

# e2e/real-stack.spec.ts imports @playwright/test and node builtins only. The
# Angular dependency tree is not needed here and is deliberately not installed.
RUN npm install --no-audit --no-fund --no-package-lock \
      "@playwright/test@${PLAYWRIGHT_VERSION}"

COPY playwright.config.ts ./
COPY e2e ./e2e

ENV CI=1
ENV F11_CHROMIUM_NO_SANDBOX=1

CMD ["npx", "playwright", "test", "--config", "playwright.config.ts"]
