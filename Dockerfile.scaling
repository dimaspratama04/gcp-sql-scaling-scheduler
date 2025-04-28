FROM golang:1.24-alpine as builder

# Set destination for COPY
WORKDIR /api

# Download Go modules
COPY go.mod go.sum ./

# Copy the source code.
COPY . .

# GET DEPDS N BUILD INTO BINARY
RUN go build -v -o /api/scheduler-scaller-db main.go

FROM alpine as runtime

WORKDIR /api

COPY --from=builder /api/scheduler-scaller-db .

COPY --from=builder /api/ .

# # Set the timezone and install CA certificates
RUN apk --no-cache add ca-certificates tzdata

ENTRYPOINT [ "/api/scheduler-scaller-db" ]
