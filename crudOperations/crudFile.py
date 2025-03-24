from models.File import File
from dbConfig import SessionLocal

def create_file(filename, encryption_algorithm, key_id):
    db = SessionLocal()
    new_file = File(filename=filename, encryption_algorithm=encryption_algorithm, key_id=key_id)
    db.add(new_file)
    db.commit()
    db.refresh(new_file)
    db.close()
    return new_file.id

def get_files():
    db = SessionLocal()
    files = db.query(File).all()
    db.close()
    return files

def delete_file(file_id):
    db = SessionLocal()
    file = db.query(File).filter(File.id == file_id).first()
    if file:
        db.delete(file)
        db.commit()
        db.close()
        return True
    db.close()
    return False