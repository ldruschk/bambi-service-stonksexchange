FROM node

ADD package.json .
RUN npm install
ADD . .

ENTRYPOINT ["npm", "start"]