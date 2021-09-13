# syntax=docker/dockerfile:1

FROM golang:1.16-alpine

WORKDIR $GOPATH/src/rocketsgraphql.app/mod

#COPY go.mod .
#COPY go.sum .
# RUN go mod tidy
COPY . .

# Download all the dependencies
RUN go get -d -v ./...

# Install the package
RUN go install -v ./...

RUN go build -o /docker-gs-ping

EXPOSE 7000

CMD [ "/docker-gs-ping" ]