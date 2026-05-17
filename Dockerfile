# Build stage
FROM node:18-alpine AS builder

WORKDIR /app

# Copy package files
COPY package*.json ./

# Install ALL dependencies (including devDependencies for TypeScript)
RUN npm ci

# Copy source code
COPY . .

# Build the application
RUN npm run build

# Production stage
FROM node:18-alpine

WORKDIR /app

# Copy package files and install production-only dependencies
COPY package*.json ./
RUN npm ci --omit=dev

# Copy compiled output from build stage
COPY --from=builder /app/dist ./dist

# Expose the port
EXPOSE 8000

# Set environment to production
ENV NODE_ENV=production

# Start the HTTP server
CMD ["npm", "start"]
