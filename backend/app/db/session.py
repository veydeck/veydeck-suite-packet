from sqlalchemy import create_engine, event, inspect, text
from sqlalchemy.orm import declarative_base, sessionmaker
from sqlalchemy.pool import StaticPool
from app.core.config import settings

# SQLite 在套件内使用单进程单库模型，单连接配合 WAL 可减少写锁竞争。
engine = create_engine(
    settings.DATABASE_URL,
    connect_args={"check_same_thread": False, "timeout": 30},
    poolclass=StaticPool,
)


@event.listens_for(engine, "connect")
def configure_sqlite_connection(dbapi_connection, _connection_record):
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA synchronous=NORMAL")
    cursor.execute("PRAGMA busy_timeout=30000")
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()


SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    # 自动创建所有表和索引
    Base.metadata.create_all(bind=engine)
    _upgrade_schema()


def _upgrade_schema():
    inspector = inspect(engine)
    if "packet_summaries" not in inspector.get_table_names():
        return

    columns = {column["name"] for column in inspector.get_columns("packet_summaries")}
    if "anomalies" not in columns:
        with engine.begin() as connection:
            connection.execute(
                text("ALTER TABLE packet_summaries ADD COLUMN anomalies VARCHAR")
            )
