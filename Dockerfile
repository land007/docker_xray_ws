FROM golang:1.24-alpine AS builder

WORKDIR /app

# 设置国内代理和构建环境
ENV CGO_ENABLED=0 \
    GO111MODULE=on

# *** 新增：安装 git 工具 ***
RUN apk add --no-cache git

# 1. 只复制go.mod文件
COPY go.mod .

# 2. 强制下载所有依赖（包括间接依赖）
RUN go mod download -x all && \
    go mod verify

# 3. 复制其余源代码
COPY . .

# 4. 确保依赖完整后再构建
RUN go mod tidy && \
    go build -v -o xray-app -ldflags "-s -w" main.go

FROM alpine:latest
WORKDIR /root/
COPY --from=builder /app/xray-app .


# *** 新增：复制 geosite.dat 和 geoip.dat 文件 ***
COPY geosite.dat .
COPY geoip.dat .

EXPOSE 20170
CMD ["./xray-app"]


# docker build -t land007/xray-app .
# docker run -it -p 20170:20170 --name xray-proxy --rm land007/xray-app