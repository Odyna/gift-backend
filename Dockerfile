# 使用官方 Node.js 镜像（选择和你的代码兼容的稳定版本）
FROM node:18-alpine

# 设置工作目录
WORKDIR /app

# 复制 package.json 和 package-lock.json
COPY package*.json ./

# 安装依赖（--production 表示只安装生产环境依赖，减少镜像体积）
RUN npm install --production

# 复制所有项目文件到工作目录
COPY . .

# 暴露你的服务端口（和你的 server.js 里的 PORT 保持一致，默认是 3000）
EXPOSE 3000

# 启动命令（和你的 package.json 里的 start 脚本保持一致）
CMD ["node", "server.js"]
