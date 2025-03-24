from models.PerformanceLog import PerformanceLog
from dbConfig import SessionLocal

def log_performance(operation, algorithm, execution_time, memory_usage):
    db = SessionLocal()
    new_log = PerformanceLog(operation=operation, algorithm=algorithm, execution_time=execution_time, memory_usage=memory_usage)
    db.add(new_log)
    db.commit()
    db.refresh(new_log)
    db.close()
    return new_log.id

def get_performance_logs():
    db = SessionLocal()
    logs = db.query(PerformanceLog).all()
    db.close()
    return logs