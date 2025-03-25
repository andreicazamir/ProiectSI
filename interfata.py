import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import time
import tracemalloc
from crudOperations.crudKey import create_key, get_keys, delete_key
from crudOperations.crudFile import create_file, get_files, delete_file
from crudOperations.crudPerformanceLog import log_performance, get_performance_logs, delete_performance_log

# Dictionar pentru algoritmi in functie de tipul de cheie
ALGORITHMS = {
    "SIMETRIC": ["AES", "DES"],
    "ASIMETRIC": ["RSA", "ECC"]
}

# Functie pentru actualizarea listei de algoritmi in functie de tipul de cheie selectata
def update_algorithm_options(event):
    selected_type = key_type_var.get()
    algorithm_dropdown["values"] = ALGORITHMS.get(selected_type, [])
    algorithm_var.set("")  # Resetare selectie

# Functie pentru generarea si salvarea cheii
def generate_and_save_key():
    key_type = key_type_var.get()
    algorithm = algorithm_var.get()
    
    if not key_type or not algorithm:
        messagebox.showerror("Eroare", "Selectati tipul de cheie si algoritmul!")
        return
    
    key_value = "RandomGeneratedValue"
    key_id = create_key(key_type, algorithm, key_value)
    messagebox.showinfo("Succes", f"Cheia a fost generata si salvata cu ID {key_id} \n Valoare cheie: {key_value}")
    refresh_keys()
    refresh_key_dropdown()

# Functie pentru actualizarea listei de chei
def refresh_keys():
    key_list.delete(*key_list.get_children())
    keys = get_keys()
    for key in keys:
        key_list.insert("", "end", values=(key.id, key.key_type, key.algorithm, key.key_value, key.created_at))

# Functie pentru stergerea unei chei selectate
def delete_selected_key():
    selected_item = key_list.selection()
    if not selected_item:
        messagebox.showerror("Eroare", "Selectati o cheie de sters!")
        return
    key_id = key_list.item(selected_item, "values")[0]
    delete_key(int(key_id))
    refresh_keys()
    refresh_key_dropdown()
    messagebox.showinfo("Succes", "Cheia a fost stearsa cu succes!")

# Functie pentru actualizarea dropdown-ului de chei
def refresh_key_dropdown():
    keys = get_keys()
    key_dropdown["values"] = [f"{key.id} - {key.algorithm}" for key in keys]

# Functie pentru selectarea unui fisier
def select_file():
    file_path = filedialog.askopenfilename()
    if file_path:
        file_var.set(file_path)

# Functie pentru salvarea unui fisier
def save_selected_file():
    file_path = file_var.get()
    selected_key = key_var.get()
    
    if not file_path or not selected_key:
        messagebox.showerror("Eroare", "Selectati un fisier si o cheie!")
        return
    
    key_id = int(selected_key.split(" - ")[0])  # Extragem ID-ul cheii
    algorithm = selected_key.split(" - ")[1]   # Extragem algoritmul cheii
    encrypted_filename = f"encrypted_{file_path.split('/')[-1]}"  # Exemplu de nume de fisier criptat
    
    # Masurare performanta
    tracemalloc.start()
    start_time = time.time()
    file_id = create_file(file_path, encrypted_filename, algorithm, key_id)
    end_time = time.time()
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    
    execution_time = (end_time - start_time) * 1000  # Convertire in milisecunde
    memory_usage = peak / 1024  # Convertire in KB
    
    log_performance("Encrypt", algorithm, execution_time, memory_usage)
   
    messagebox.showinfo("Succes", f"Fisierul a fost salvat cu ID {file_id}")
    refresh_files()
    refresh_performance_logs()

def delete_selected_file():
    selected_item = file_list.selection()
    if not selected_item:
        messagebox.showerror("Eroare", "Selectati un fisier de sters!")
        return
    file_id = file_list.item(selected_item, "values")[0]
    delete_file(int(file_id))
    refresh_files()
    messagebox.showinfo("Succes", "Fisierul a fost sters cu succes!")

def refresh_files():
    file_list.delete(*file_list.get_children())
    files = get_files()
    for file in files:
        file_list.insert("", "end", values=(
            file.id, file.filename, file.encrypted_filename, file.encryption_algorithm, file.key_id, file.created_at
        ))

def refresh_performance_logs():
    tree.delete(*tree.get_children())
    logs = get_performance_logs()
    for log in logs:
        tree.insert("", "end", values=(log.id, log.operation, log.algorithm, log.execution_time, log.memory_usage))

# Functie pentru stergerea unei intrari din performance log
def delete_selected_performance_log():
    selected_item = tree.selection()
    if not selected_item:
        messagebox.showerror("Eroare", "Selectati o intrare de sters din log-ul de performanta!")
        return
    log_id = tree.item(selected_item, "values")[0]
    delete_performance_log(int(log_id))
    refresh_performance_logs()
    messagebox.showinfo("Succes", "Intrarea a fost stearsa din log-ul de performanta!")

# Creare fereastra principala
root = tk.Tk()
root.title("Management Chei & Fisiere")
root.geometry("1250x500")

# Notebook pentru navigare
notebook = ttk.Notebook(root)
notebook.pack(expand=True, fill="both")

# Tab Key Management
key_frame = ttk.Frame(notebook)
notebook.add(key_frame, text="Chei")

# Selectare tip de cheie
tk.Label(key_frame, text="Tip cheie:").grid(row=0, column=0, padx=5)
key_type_var = tk.StringVar()
key_type_dropdown = ttk.Combobox(key_frame, textvariable=key_type_var, values=list(ALGORITHMS.keys()), state="readonly")
key_type_dropdown.grid(row=0, column=1, padx=5)
key_type_dropdown.bind("<<ComboboxSelected>>", update_algorithm_options)

# Selectare algoritm
tk.Label(key_frame, text="Algoritm:").grid(row=0, column=2, padx=5)
algorithm_var = tk.StringVar()
algorithm_dropdown = ttk.Combobox(key_frame, textvariable=algorithm_var, state="readonly")
algorithm_dropdown.grid(row=0, column=3, padx=5)

# Buton generare cheie
generate_button = tk.Button(key_frame, text="Genereaza si salveaza cheia", command=generate_and_save_key).grid(row=0, column=4, padx=5)

# Buton stergere cheie
delete_button = tk.Button(key_frame, text="Sterge cheia", command=delete_selected_key).grid(row=0, column=5, padx=5)

# Lista chei
tk.Label(key_frame, text="Chei salvate:").grid(row=1, column=0, columnspan=6)

key_list = ttk.Treeview(key_frame, columns=("ID", "Tip", "Algoritm", "Valoare", "Creat"), show="headings")
key_list.grid(row=2, column=0, columnspan=6, sticky="nsew")

key_list.heading("ID", text="ID")
key_list.heading("Tip", text="Tip")
key_list.heading("Algoritm", text="Algoritm")
key_list.heading("Valoare", text="Valoare")
key_list.heading("Creat", text="Creat la")

key_frame.grid_columnconfigure(0, weight=1)
key_frame.grid_rowconfigure(2, weight=1)

refresh_keys()

# Tab File Management
file_frame = ttk.Frame(notebook)
notebook.add(file_frame, text="Fișiere")

# Selectare fisier
tk.Label(file_frame, text="Selectare fisier:").grid(row=0, column=0, padx=5)
file_var = tk.StringVar()
file_entry = tk.Entry(file_frame, textvariable=file_var, width=50).grid(row=0, column=1, padx=5)
select_file_button = tk.Button(file_frame, text="Alege fisier", command=select_file).grid(row=0, column=2, padx=5)

# Selectare cheie pentru criptare
tk.Label(file_frame, text="Selectati cheia:").grid(row=0, column=3, padx=5)
key_var = tk.StringVar()
key_dropdown = ttk.Combobox(file_frame, textvariable=key_var, state="readonly")
key_dropdown.grid(row=0, column=4, padx=5)
refresh_key_dropdown()

# Buton salvare fișier
save_file_button = tk.Button(file_frame, text="Salvează fisier", command=save_selected_file).grid(row=0, column=5, padx=5)
delete_file_button = tk.Button(file_frame, text="Sterge fisier", command=delete_selected_file).grid(row=0, column=6, padx=5)


# Listă fișiere
tk.Label(file_frame, text="Fisiere salvate:").grid(row=1, column=0, columnspan=6)

file_list = ttk.Treeview(file_frame, columns=("ID", "Nume", "Fisier criptat", "Algoritm", "Cheie ID", "Creat"), show="headings")
file_list.grid(row=2, column=0, columnspan=6, sticky="nsew")

file_list.heading("ID", text="ID")
file_list.heading("Nume", text="Nume Fisier")
file_list.heading("Fisier criptat", text="Fisier Criptat")
file_list.heading("Algoritm", text="Algoritm")
file_list.heading("Cheie ID", text="ID Cheie")
file_list.heading("Creat", text="Creat la")

# Asigura ca tabelul se ajustează corect
file_frame.grid_columnconfigure(0, weight=1)
file_frame.grid_rowconfigure(2, weight=1)

refresh_files()

# Tab Performanta
performance_tab = ttk.Frame(notebook)
notebook.add(performance_tab, text="Performanta")

delete_log_button = tk.Button(performance_tab, text="Sterge Performanta", command=delete_selected_performance_log)
delete_log_button.grid(row=0, column=0, padx=5, pady=5)

# Tabel Performance Logs
tree = ttk.Treeview(performance_tab, columns=("ID", "Operatie", "Algoritm", "Timp", "Memorie"), show="headings")
tree.grid(row=2, column=0, columnspan=6, sticky="nsew")
tree.heading("ID", text="ID")
tree.heading("Operatie", text="Operatie")
tree.heading("Algoritm", text="Algoritm")
tree.heading("Timp", text="Timp (ms)")
tree.heading("Memorie", text="Memorie (KB)")

performance_tab.grid_columnconfigure(0, weight=1)
performance_tab.grid_rowconfigure(2, weight=1)

refresh_performance_logs()

root.mainloop()