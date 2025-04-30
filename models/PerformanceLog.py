from sqlalchemy import Column, Integer, String, DateTime, ForeignKey
from datetime import datetime
from dbConfig import Base

class PerformanceLog(Base):
    __tablename__ = "performance_logs"
    id = Column(Integer, primary_key=True, autoincrement=True)
    operation = Column(String(50)) 
    algorithm = Column(String(50))
    fisier = Column(String(250))
    execution_time = Column(Integer)
    execution_time_per_bit = Column(Integer)
    memory_usage = Column(Integer) 
    memory_usage_per_bit = Column(Integer) 
    created_at = Column(DateTime, default=datetime.utcnow)
