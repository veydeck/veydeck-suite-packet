from pathlib import Path

from pydantic_settings import SettingsConfigDict
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    model_config = SettingsConfigDict(case_sensitive=True)

    PROJECT_NAME: str = "Packet"
    API_V1_STR: str = "/api"

    # 检测 /data 目录是否存在，以决定是否在持久化路径上工作
    DATA_ROOT: Path = Path("/data") if Path("/data").exists() else Path("./")

    @property
    def DATABASE_URL(self) -> str:
        db_path = self.DATA_ROOT / "packet.db"
        # 返回 sqlite 的绝对路径形式
        return f"sqlite:///{db_path.resolve()}"

    @property
    def UPLOAD_DIR(self) -> Path:
        path = self.DATA_ROOT / "uploads"
        path.mkdir(parents=True, exist_ok=True)
        return path

    @property
    def GENERATED_DIR(self) -> Path:
        path = self.DATA_ROOT / "generated"
        path.mkdir(parents=True, exist_ok=True)
        return path

    # 上传与解析安全限制
    MAX_FILE_SIZE: int = 100 * 1024 * 1024  # 100 MB
    MAX_PACKET_COUNT: int = 200_000  # 最大解析包数
    BATCH_SIZE: int = 1000  # 数据库批量插入大小
    ALLOWED_PCAP_EXTENSIONS: tuple[str, ...] = (".pcap", ".pcapng")
    MAX_BUILD_PACKET_COUNT: int = 5000


settings = Settings()
