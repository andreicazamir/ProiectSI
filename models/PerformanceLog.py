from sqlalchemy import Column, Integer, String, DateTime
from datetime import datetime
from dbConfig import Base

class PerformanceLog(Base):
    __tablename__ = "performance_logs"
    id = Column(Integer, primary_key=True, autoincrement=True)
    operation = Column(String(50)) 
    algorithm = Column(String(50))
    execution_time = Column(Integer)
    memory_usage = Column(Integer) 
    created_at = Column(DateTime, default=datetime.utcnow)
