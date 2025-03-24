from dbConfig import Base, engine
from crudOperations.crudKey import create_key, get_keys, update_key, delete_key
from crudOperations.crudFile import create_file, get_files, delete_file
from crudOperations.crudPerformanceLog import log_performance, get_performance_logs


Base.metadata.create_all(engine)

if __name__ == "__main__":
    print("Adăugare cheie...")
    key_id = create_key("SIMETRIC", "AES", "123456789abcdef")
    print(f"Cheia adăugată cu ID: {key_id}")

    print("Adăugare fișier...")
    file_id = create_file("document.txt", "AES", key_id)
    print(f"Fișier adăugat cu ID: {file_id}")

    print("Măsurare performanță...")
    log_id = log_performance("Encrypt", "AES", 120, 500)
    print(f"Performanță logată cu ID: {log_id}")

    print("Listare chei...")
    keys = get_keys()
    for key in keys:
        print(f"ID: {key.id}, Algoritm: {key.algorithm}")

    print("Listare fișiere...")
    files = get_files()
    for file in files:
        print(f"ID: {file.id}, Nume: {file.filename}, Algoritm: {file.encryption_algorithm}")

    print("Listare loguri de performanță...")
    logs = get_performance_logs()
    for log in logs:
        print(f"ID: {log.id}, Operație: {log.operation}, Algoritm: {log.algorithm}, Timp: {log.execution_time} ms, Memorie: {log.memory_usage} KB")

    print("Ștergere fișier...")
    delete_file(file_id)
    
    print("Ștergere cheie...")
    delete_key(key_id)

    print("Verificare chei după ștergere...")
    keys = get_keys()
    print("Chei existente:", len(keys))