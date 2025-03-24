from sqlalchemy import Column, Integer, String, Text, Boolean, DateTime, ForeignKey
from datetime import datetime
from dbConfig import Base

class File(Base):
    __tablename__ = "files"
    id = Column(Integer, primary_key=True, autoincrement=True)
    filename = Column(String(255), nullable=False)
    encrypted_filename = Column(String(255), nullable=True)
    encryption_algorithm = Column(String(50))
    key_id = Column(Integer, ForeignKey("keys.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)