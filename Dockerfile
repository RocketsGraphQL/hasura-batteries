# syntax=docker/dockerfile:1
# amd64 is fix for porting from mac m1 to linux on AWS
FROM --platform=linux/amd64 golang:1.16-alpine

WORKDIR $GOPATH/src/rocketsgraphql.app/mod

#COPY go.mod .
#COPY go.sum .
# RUN go mod tidy
COPY . .

# Download all the dependencies
RUN go get -d -v ./...

# Install the package
RUN go install -v ./...

ENV APP_ENV=production

RUN go build -o /docker-gs-ping

EXPOSE 8000

CMD [ "/docker-gs-ping" ]
