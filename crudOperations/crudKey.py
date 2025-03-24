from models.Key import Key
from dbConfig import SessionLocal

def create_key(key_type, algorithm, key_value):
    db = SessionLocal()
    new_key = Key(key_type=key_type, algorithm=algorithm, key_value=key_value)
    db.add(new_key)
    db.commit()
    db.refresh(new_key)
    db.close()
    return new_key.id

def get_keys():
    db = SessionLocal()
    keys = db.query(Key).all()
    db.close()
    return keys

def update_key(key_id, new_algorithm):
    db = SessionLocal()
    key = db.query(Key).filter(Key.id == key_id).first()
    if key:
        key.algorithm = new_algorithm
        db.commit()
        db.close()
        return True
    db.close()
    return False

def delete_key(key_id):
    db = SessionLocal()
    key = db.query(Key).filter(Key.id == key_id).first()
    if key:
        db.delete(key)
        db.commit()
        db.close()
        return True
    db.close()
    return False