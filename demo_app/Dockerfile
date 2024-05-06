FROM golang:1.22.1
WORKDIR /app

COPY go.mod /app
RUN go mod download

COPY .. /app

RUN rm metro || true

RUN go build -buildvcs=false -o demo_app .

CMD ["./demo_app"]
