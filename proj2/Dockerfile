FROM alpine:3.7
EXPOSE 3000
RUN adduser -S cs155
ADD code/ /home/cs155/proj2/
WORKDIR /home/cs155/proj2/
RUN apk update && \
    apk add --update nodejs && \
    npm install --global yarn && \
    yarn
CMD ["yarn", "start"]

# commands:
    # docker build -t cs155-proj2-image .
    # docker run -it --rm -p 3000:3000 --mount type=bind,source="$(pwd)"/code/router.js,target=/home/cs155/proj2/router.js cs155-proj2-image
