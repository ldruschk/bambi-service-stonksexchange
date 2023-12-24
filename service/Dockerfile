FROM node

WORKDIR /service
ADD package.json .
RUN npm install
ADD . .

ENTRYPOINT ["npm", "start"]
