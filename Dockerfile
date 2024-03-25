FROM golang:alpine as go
WORKDIR /fbhosts
COPY go.* .
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -extldflags=-static" .

FROM alpine
COPY --from=go /fbhosts/fbhosts /usr/local/bin
ENTRYPOINT ["fbhosts"]
WORKDIR /fbhosts
