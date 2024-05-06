FROM golang:1.22.1
WORKDIR /app

COPY go.mod /app
RUN go mod download

COPY . /app

RUN go build -buildvcs=false -o yash_demo .
RUN chmod +x yash_demo

CMD ["./yash_demo"]
