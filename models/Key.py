from sqlalchemy import Column, Integer, String, Text, Enum, DateTime
from datetime import datetime
from dbConfig import Base

class Key(Base):
    __tablename__ = "keys"
    id = Column(Integer, primary_key=True, autoincrement=True)
    key_type = Column(Enum('SIMETRIC', 'ASIMETRIC'))
    algorithm = Column(String(50))
    key_value = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)