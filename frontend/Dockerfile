FROM node:20-alpine

WORKDIR /app

COPY package*.json ./
RUN npm install

COPY . .

# Run Vite in dev mode bound to 0.0.0.0 so it is accessible outside the container
CMD ["npm", "run", "dev", "--", "--host", "0.0.0.0"]
