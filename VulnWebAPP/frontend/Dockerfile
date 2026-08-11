FROM node:20-alpine

WORKDIR /app
COPY package.json ./
RUN npm install
COPY index.html ./
COPY vite.config.js ./
COPY src ./src
RUN npm run build
EXPOSE 5173
CMD ["npm", "run", "dev", "--", "--host", "0.0.0.0"]
