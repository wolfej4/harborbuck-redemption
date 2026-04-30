FROM node:20-alpine

WORKDIR /app

# Build tools for better-sqlite3 native bindings, and tzdata for the configured timezone
RUN apk add --no-cache python3 make g++ tzdata

ENV TZ=America/Chicago

COPY package*.json ./
RUN npm install --production

COPY server.js ./
COPY index.html login.html setup.html register.html \
     mfa.html mfa-setup.html admin.html settings.html \
     metrics.html reset-request.html reset-confirm.html \
     manifest.json sw.js icon.svg icon-maskable.svg \
     ./public/

# SQLite data directory — mount a volume here
VOLUME ["/data"]

EXPOSE 3000

CMD ["node", "server.js"]
