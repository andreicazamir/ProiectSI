from sqlalchemy import Column, Integer, String, DateTime
from datetime import datetime
from dbConfig import Base

class PerformanceLog(Base):
    __tablename__ = "performance_logs"
    id = Column(Integer, primary_key=True, autoincrement=True)
    operation = Column(String(50))  # Encrypt / Decrypt
    algorithm = Column(String(50))
    execution_time = Column(Integer)  # Milisecunde
    memory_usage = Column(Integer)  # Kilobytes
    created_at = Column(DateTime, default=datetime.utcnow)
