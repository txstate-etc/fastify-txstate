FROM node:12-alpine
WORKDIR /usr/app

COPY package.json ./
RUN npm install

COPY test test

ENTRYPOINT [ "npm" ]
CMD [ "run", "mocha" ]
