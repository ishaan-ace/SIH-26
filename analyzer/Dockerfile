FROM golang:1.23-alpine

RUN apk add --no-cache libpcap-dev gcc g++ linux-headers

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN go build -o analyzer .

CMD ["./analyzer"]
