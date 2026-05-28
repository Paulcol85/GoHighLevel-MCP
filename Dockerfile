FROM node:18-alpine

WORKDIR /app

# Copy package files and install ALL deps (including devDeps for ts-node + typescript)
COPY package*.json ./
RUN npm install

# Copy source
COPY . .

EXPOSE 8000

# Set production env AFTER npm install so devDeps are installed above
ENV NODE_ENV=production

# Run TypeScript directly - no build step, no type checking
CMD ["npm", "start"]