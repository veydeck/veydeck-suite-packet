FROM python:3.13-slim

LABEL veydeck.owner="suite"

# 安装运行所需的系统工具（如 curl 用于健康检查）
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# 从官方镜像导入 uv 用于依赖管理
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

# 拷贝后端依赖并同步
COPY backend/pyproject.toml backend/uv.lock ./
RUN uv sync --frozen --no-cache

# 拷贝后端代码（把 app 目录和 main.py 拷贝到工作区）
COPY backend/main.py ./
COPY backend/app ./app

# 拷贝前端构建出的 dist 目录到容器的 static 目录中
COPY frontend/dist ./static

# 将 Python 虚拟环境的 bin 目录加入 PATH
ENV PATH="/app/.venv/bin:$PATH"
ENV PYTHONUNBUFFERED=1

EXPOSE 8080

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
