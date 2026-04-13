FROM node:20-alpine

WORKDIR /app

# Build tools for better-sqlite3 native bindings
RUN apk add --no-cache python3 make g++

COPY package*.json ./
RUN npm install --production

COPY server.js ./
COPY index.html login.html setup.html register.html \
     mfa.html mfa-setup.html admin.html settings.html \
     reset-request.html reset-confirm.html \
     ./public/

# SQLite data directory — mount a volume here
VOLUME ["/data"]

EXPOSE 3000

CMD ["node", "server.js"]
