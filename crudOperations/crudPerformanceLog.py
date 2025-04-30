from models.PerformanceLog import PerformanceLog
from dbConfig import SessionLocal

def log_performance(operation, algorithm, execution_time, execution_time_per_bit, memory_usage, memory_usage_per_bit, file):
    db = SessionLocal()
    new_log = PerformanceLog(operation=operation, algorithm=algorithm, execution_time=execution_time, execution_time_per_bit=execution_time_per_bit, memory_usage=memory_usage, memory_usage_per_bit=memory_usage_per_bit, fisier=file)
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

def delete_performance_log(log_id):
    db = SessionLocal()
    log = db.query(PerformanceLog).filter(PerformanceLog.id == log_id).first()
    if log:
        db.delete(log)
        db.commit()
        db.close()
        return True
    db.close()
    return False