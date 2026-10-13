import os
import logging
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.core.config import settings
from app.db.session import init_db
from app.api.pcaps import router as pcaps_router
from app.api.packets import router as packets_router
from app.api.stats import router as stats_router
from app.api.builders import router as builders_router

# 设置基本日志
logging.basicConfig(
    level=logging.INFO,
    format="%(levelname)s [%(name)s] %(message)s",
)
logger = logging.getLogger(__name__)

# 初始化数据库结构
try:
    init_db()
    logger.info("Database tables initialized successfully.")
except Exception as e:
    logger.error(f"Failed to initialize database: {e}")

app = FastAPI(title=settings.PROJECT_NAME, version="0.1.0-alpha.1")

# 启用 CORS，方便本地跨端开发调试
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 注册 API 路由
app.include_router(pcaps_router, prefix="/api/pcaps", tags=["pcaps"])
app.include_router(
    packets_router, prefix="/api/pcaps/{pcap_id}/packets", tags=["packets"]
)
app.include_router(stats_router, prefix="/api/pcaps/{pcap_id}/stats", tags=["stats"])
app.include_router(builders_router, prefix="/api", tags=["builders"])


# 健康检查接口
@app.get("/health")
def health_check():
    return {"status": "ok", "ok": True}


# SPA 静态文件映射与 Fallback 处理器
class SPAStaticFiles(StaticFiles):
    async def get_response(self, path: str, scope):
        try:
            return await super().get_response(path, scope)
        except (HTTPException, StarletteHTTPException) as e:
            if e.status_code == 404:
                # 只让前端路由回退到 index.html；静态资源缺失必须返回 404，
                # 否则浏览器加载 JS/CSS 时会收到 text/html 并触发 MIME 错误。
                is_api_path = path.startswith("api/") or path == "api"
                is_static_asset = path.startswith("assets/") or "." in os.path.basename(
                    path
                )
                if not is_api_path and not is_static_asset:
                    return await super().get_response("index.html", scope)
            raise e


# 检测并挂载前端静态文件目录
static_dir = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "static")
)
if not os.path.exists(static_dir):
    static_dir = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "static")
    )

if os.path.exists(static_dir) and os.path.exists(
    os.path.join(static_dir, "index.html")
):
    logger.info(f"Mounting frontend static files from: {static_dir}")
    app.mount("/", SPAStaticFiles(directory=static_dir, html=True), name="static")
else:
    logger.warning(
        f"Static directory not found or index.html missing at {static_dir}. Frontend will not be served."
    )

    @app.get("/")
    def index_fallback():
        return {
            "message": "Welcome to Packet backend! Frontend assets are not compiled yet."
        }
