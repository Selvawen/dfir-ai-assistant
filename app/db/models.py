from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy import String, Integer, Text, DateTime, func

class Base(DeclarativeBase):
    pass

class Case(Base):
    __tablename__ = "cases"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    status: Mapped[str] = mapped_column(String(30), nullable=False, default="Open")
    created_at: Mapped[str] = mapped_column(DateTime(timezone=True), server_default=func.now())

class Event(Base):
    __tablename__ = "events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    case_id: Mapped[int] = mapped_column(Integer, index=True)

    ts: Mapped[str] = mapped_column(String(50), index=True)  # ISO8601 string
    host: Mapped[str] = mapped_column(String(200), default="unknown")
    channel: Mapped[str] = mapped_column(String(100), default="unknown")
    event_id: Mapped[str] = mapped_column(String(50), default="unknown")
    level: Mapped[str] = mapped_column(String(50), default="unknown")
    user: Mapped[str] = mapped_column(String(200), default="unknown")
    src_ip: Mapped[str] = mapped_column(String(100), default="")

    # NEW: process-related fields (Sysmon / EDR exports)
    process_name: Mapped[str] = mapped_column(String(260), default="")
    command_line: Mapped[str] = mapped_column(Text, default="")
    parent_process: Mapped[str] = mapped_column(String(260), default="")

    # NEW: logon context (Windows Security 4624/4625)
    logon_type: Mapped[str] = mapped_column(String(50), default="")

    raw_json: Mapped[str] = mapped_column(Text, nullable=False)