FROM golang:1.22.1
WORKDIR /app

COPY go.mod /app
RUN go mod download

COPY . /app

RUN go build -buildvcs=false -o public_private_key_pair .

CMD ["/app/public_private_key_pair"]

