import os
import subprocess
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import time
import tracemalloc
import re
from crudOperations.crudKey import create_key, get_keys, delete_key
from crudOperations.crudFile import create_file, get_files, delete_file
from crudOperations.crudPerformanceLog import log_performance, get_performance_logs, delete_performance_log

# Dictionar pentru algoritmi in functie de tipul de cheie
ALGORITHMS = {
    "SIMETRIC": ["AES - OPENSSL", "DES - OPENSSL", "AES - WINDOWSCND", "DES - WINDOWSCND"],
    "ASIMETRIC": ["RSA - OPENSSL", "RSA - WINDOWSCND"]
}

TIPMETODA = ["CRIPTARE", "DECRIPTARE"]

# Functie pentru actualizarea listei de algoritmi in functie de tipul de cheie selectata
def update_algorithm_options(event):
    selected_type = key_type_var.get()
    algorithm_dropdown["values"] = ALGORITHMS.get(selected_type, [])
    algorithm_var.set("") 

# Functie pentru generarea si salvarea cheii
def generate_and_save_key():
    key_type = key_type_var.get()
    algorithmFramework = algorithm_var.get()
    algorithm, framework = algorithmFramework.split(" - ")
    
    if not key_type or not algorithm:
        messagebox.showerror("Eroare", "Selectati tipul de cheie si algoritmul!")
        return
    
    key_value = "RandomGeneratedValue"

    try:
        if key_type == "SIMETRIC":
            if algorithm == "AES":
                if framework == "OPENSSL":
                    key_value = subprocess.check_output(
                        ["openssl", "rand", "-hex", "32"], text=True).strip()
                elif framework == "WINDOWSCND":
                    command = '''
                    [byte[]]$key = New-Object byte[] 32;
                    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($key);
                    ($key | ForEach-Object { $_.ToString("X2") }) -join ""
                    '''
                    key_value = subprocess.check_output(
                        ["powershell", "-Command", command], text=True).strip()
                else:
                    raise ValueError("Framework inexistent.")
            elif algorithm == "DES":
                if framework == "OPENSSL":
                    key_value = subprocess.check_output(
                        ["openssl", "rand", "-hex", "8"], text=True).strip()
                elif framework == "WINDOWSCND":
                    command = '''
                    [byte[]]$key = New-Object byte[] 8;
                    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($key);
                    ($key | ForEach-Object { $_.ToString("X2") }) -join ""
                    '''
                    key_value = subprocess.check_output(
                        ["powershell", "-Command", command], text=True).strip()
                else:
                    raise ValueError("Framework necunoscut.")
            else:
                raise ValueError("Algoritm simetric necunoscut.")
        
        elif key_type == "ASIMETRIC":
            if algorithm == "RSA":
                if framework == "OPENSSL":
                    priv_result = subprocess.run(
                        ["openssl", "genrsa", "2048"],
                        capture_output=True, text=True, check=True
                    )
                    private_key = priv_result.stdout.strip()

                    pub_result = subprocess.run(
                        ["openssl", "rsa", "-pubout"],
                        input=private_key,
                        capture_output=True, text=True, check=True
                    )
                    public_key = pub_result.stdout.strip()

                    key_value = f"{private_key}###KEY_SEPARATOR###{public_key}"
                elif framework == "WINDOWSCND":
                    command = '''
                    $cert = New-SelfSignedCertificate -KeyAlgorithm RSA -KeyLength 2048 -CertStoreLocation "Cert:\\CurrentUser\\My" -Subject "CN=TempCert";
                    $pfxPath = "$env:TEMP\\temp.pfx";
                    $cerPath = "$env:TEMP\\temp.cer";
                    $pwd = ConvertTo-SecureString -String "temp1234" -Force -AsPlainText;
                    Export-PfxCertificate -Cert $cert -FilePath $pfxPath -Password $pwd | Out-Null;
                    Export-Certificate -Cert $cert -FilePath $cerPath | Out-Null;
                    $pfxBytes = Get-Content -Path $pfxPath -Encoding Byte;
                    $cerBytes = Get-Content -Path $cerPath -Encoding Byte;
                    $pfxBase64 = [Convert]::ToBase64String($pfxBytes);
                    $cerBase64 = [Convert]::ToBase64String($cerBytes);
                    Remove-Item $pfxPath;
                    Remove-Item $cerPath;
                    Write-Output "$pfxBase64###KEY_SEPARATOR###$cerBase64"
                    '''
                    key_value = subprocess.check_output(
                        ["powershell", "-Command", command], text=True).strip()
                else:
                    raise ValueError("Framework inexistent.")
            else:
                raise ValueError("Algoritm asimetric necunoscut.")

        else:
            raise ValueError("Tip de cheie necunoscut.")
    
    except subprocess.CalledProcessError as e:
        messagebox.showerror("Eroare OpenSSL", f"Eroare la executia comenzii OpenSSL:\n{e.stderr}")
        return
    except Exception as e:
        messagebox.showerror("Eroare", f"A aparut o eroare la generarea cheii:\n{e}")
        return

    key_id = create_key(key_type, algorithmFramework, key_value)
    messagebox.showinfo("Succes", f"Cheia a fost generata si salvata cu ID {key_id}\n")
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
    key_dropdown["values"] = [f"{key.id} - {key.algorithm} - {key.created_at}" for key in keys]

# Functie pentru selectarea unui fisier
def select_file():
    file_path = filedialog.askopenfilename()
    if file_path:
        file_var.set(file_path)

# Functie pentru salvarea unui fisier
def save_selected_file():
    file_path = file_var.get()
    selected_key = key_var.get()
    selected_operation = operatie_var.get()

    file_size_in_bytes = os.path.getsize(file_path)
    total_bits = file_size_in_bytes * 8
    
    if not file_path or not selected_key or not selected_operation:
        messagebox.showerror("Eroare", "Selectati un fisier si o cheie!")
        return
    
    key_id = int(selected_key.split(" - ")[0])  # Extracting the key ID
    algorithm = selected_key.split(" - ")[1]   # Extracting the algorithm from the selected key
    framework = selected_key.split(" - ")[2]

    keys = get_keys()
    key_value = None
    for key in keys:
        if key.id == key_id:
            key_value = key.key_value
            break
    
    if not key_value:
        messagebox.showerror("Eroare", "Cheia selectata nu a fost gasita in baza de date!")
        return

    file_dir = os.path.dirname(file_path)
    base_name = os.path.splitext(os.path.basename(file_path))[0] 
    
    #Masurare performanta
    tracemalloc.start()
    start_time = time.time()
    if ("PRIVATE KEY" in key_value and "PUBLIC KEY" in key_value) or "###KEY_SEPARATOR###" in key_value:
        try:
            if selected_operation == "CRIPTARE":
                filenameBD = encrypted_filename = os.path.join(file_dir, f"encrypted_{algorithm}_{framework}_{base_name}.enc")
                if framework == "OPENSSL":
                    if algorithm == "RSA":
                        private_key, public_key = key_value.split("###KEY_SEPARATOR###")

                        public_key_file = "public_key.pem"
                        with open(public_key_file, "w") as f:
                            f.write(public_key)
                        
                        result = subprocess.run(
                            ["openssl", "rsautl", "-provider", "legacy", "-provider", "default", "-encrypt", "-inkey", public_key_file, "-pubin", "-in", file_path, "-out", encrypted_filename],
                            check=True
                        )
                        os.remove(public_key_file)
                    else:
                        messagebox.showerror("Eroare", "Algoritm de criptare necunoscut pentru cheia asimetrica!")
                        return
                elif framework == "WINDOWSCND":
                    if algorithm == "RSA":
                        public_key_xml = key_value.split("###KEY_SEPARATOR###")[1]
                        ps_script_rsa = f"""
$PublicKeyXml = @'
{public_key_xml}
'@

$InputFile = '{file_path}'
$OutputFile = '{encrypted_filename}'

# Citim datele din fișier
$Data = [System.IO.File]::ReadAllBytes($InputFile)

# Creăm obiectul RSA și importăm cheia publică
$RSA = New-Object System.Security.Cryptography.RSACryptoServiceProvider
$RSA.PersistKeyInCsp = $false
$RSA.FromXmlString($PublicKeyXml)

# Criptăm datele
$EncryptedData = $RSA.Encrypt($Data, $true)

# Scriem datele criptate în fișierul de ieșire
[System.IO.File]::WriteAllBytes($OutputFile, $EncryptedData)
"""
                        try:
                            subprocess.run(["powershell", "-Command", ps_script_rsa], capture_output=True, check=True, text=True)
                        except subprocess.CalledProcessError as e:
                            messagebox.showerror("Eroare PowerShell", f"Eroare la criptarea RSA în CMD: {e.stderr}")
                            print(e.stderr)
                            return
                    else:
                        messagebox.showerror("Eroare", "Algoritm de criptare necunoscut pentru cheia asimetrica!")
                        return
                else:
                    raise ValueError("Framework neimplementat.")
            elif selected_operation == "DECRIPTARE":
                filenameBD = decrypted_filename = os.path.join(file_dir, f"decrypted_{algorithm}_{framework}_{base_name}.txt")
                if framework == "OPENSSL":
                    if algorithm == "RSA":
                        private_key = key_value.split("###KEY_SEPARATOR###")[0]

                        private_key_file = "private_key.pem"
                        with open(private_key_file, "w") as f:
                            f.write(private_key)
                        
                        result = subprocess.run(
                            ["openssl", "rsautl", "-provider", "legacy", "-provider", "default", "-decrypt", "-inkey", private_key_file, "-in", file_path, "-out", decrypted_filename],
                            check=True
                        )
                        os.remove(private_key_file)
                    else:
                        messagebox.showerror("Eroare", "Algoritm de decriptare necunoscut pentru cheia asimetrica!")
                        return
                elif framework == "WINDOWSCND":
                    if algorithm == "RSA":
                        return 
                    else:
                        messagebox.showerror("Eroare", "Algoritm de decriptare necunoscut pentru cheia asimetrica!")
                        return
                else:
                    raise ValueError("Framework neimplementat.")
            else:
                raise ValueError("Operatie neimplementata.")
            
        except subprocess.CalledProcessError as e:
            messagebox.showerror("Eroare OpenSSL", f"Eroare la criptarea fisierului: {e.stderr}")
            print(e.stderr)
            return
        except Exception as e:
            messagebox.showerror("Eroare", f"A aparut o eroare la {selected_operation}a fisierului:\n{e}")
            print(e)
            return
    else:
        try:
            if selected_operation == "CRIPTARE":
                filenameBD = encrypted_filename = os.path.join(file_dir, f"encrypted_{algorithm}_{framework}_{base_name}.enc")
                if framework == "OPENSSL":
                    if algorithm == "AES":
                        result = subprocess.run(
                            ["openssl", "enc", "-aes-256-cbc", "-salt", "-in", file_path, "-out", encrypted_filename, "-pass", f"pass:{key_value}"],
                            capture_output=True, text=True, check=True
                        ) 
                    elif algorithm == "DES":
                        result = subprocess.run(
                            ["openssl", "enc", "-des-cbc", "-provider", "legacy", "-provider", "default", "-salt", "-in", file_path, "-out", encrypted_filename, "-pass", f"pass:{key_value}"],
                            capture_output=True, text=True, check=True
                        )
                    else:
                        messagebox.showerror("Eroare", "Algoritm de criptare necunoscut!")
                        return
                elif framework == "WINDOWSCND":
                    if algorithm == "AES":
                        ps_script = f"""
                        $Key = ConvertTo-SecureString -String '{key_value}' -AsPlainText -Force
                        $KeyBytes = [System.Text.Encoding]::UTF8.GetBytes($Key)

                        $IV = New-Object Byte[] 16
                        [System.Security.Cryptography.RNGCryptoServiceProvider]::Create().GetBytes($IV)
                                
                        $AES = New-Object System.Security.Cryptography.AesManaged
                        $AES.Key = $KeyBytes
                        $AES.IV = $IV
                        $AES.Mode = [System.Security.Cryptography.CipherMode]::CBC
                        $AES.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
                        $Encryptor = $AES.CreateEncryptor()

                        $InputFile = '{file_path}'
                        $OutputFile = '{encrypted_filename}'

                        $Data = [System.IO.File]::ReadAllBytes($InputFile)
                        $EncryptedData = $Encryptor.TransformFinalBlock($Data, 0, $Data.Length)

                        [System.IO.File]::WriteAllBytes($OutputFile, $IV + $EncryptedData)
                        """
                        try:
                            subprocess.run(["powershell", "-Command", ps_script], check=True)
                        except subprocess.CalledProcessError as e:
                            messagebox.showerror("Eroare PowerShell", f"Eroare la criptarea fisierului: {e.stderr}")
                            print(e.stderr)
                            return

                    elif algorithm == "DES":
                        ps_script_des = f"""
                        $Key = ConvertTo-SecureString -String '{key_value}' -AsPlainText -Force
                        $KeyBytes = [System.Text.Encoding]::UTF8.GetBytes($Key)

                        $IV = New-Object Byte[] 8
                        [System.Security.Cryptography.RNGCryptoServiceProvider]::Create().GetBytes($IV)
                                        
                        $DES = New-Object System.Security.Cryptography.DESCryptoServiceProvider
                        $DES.Key = $KeyBytes
                        $DES.IV = $IV
                        $DES.Mode = [System.Security.Cryptography.CipherMode]::CBC
                        $DES.Padding = [System.Security.Cryptography.PaddingMode]::Zeros
                        $Encryptor = $DES.CreateEncryptor()

                        $InputFile = '{file_path}'
                        $OutputFile = '{encrypted_filename}'

                        $Data = [System.IO.File]::ReadAllBytes($InputFile)
                        $EncryptedData = $Encryptor.TransformFinalBlock($Data, 0, $Data.Length)

                        [System.IO.File]::WriteAllBytes($OutputFile, $IV + $EncryptedData)
                        """
                        try:
                            subprocess.run(["powershell", "-Command", ps_script_des], check=True)
                        except subprocess.CalledProcessError as e:
                            messagebox.showerror("Eroare PowerShell", f"Eroare la criptarea fisierului: {e.stderr}")
                            print(e.stderr)
                            return
                    else:
                        messagebox.showerror("Eroare", "Algoritm de criptare necunoscut!")
                        return

                else:
                    raise ValueError("Framework neimplementat.")
            elif selected_operation == "DECRIPTARE":
                filenameBD = decrypted_filename = os.path.join(file_dir, f"decrypted_{algorithm}_{framework}_{base_name}.txt")
                if framework == "OPENSSL":
                    if algorithm == "AES":
                        result = subprocess.run(
                            ["openssl", "enc", "-aes-256-cbc", "-d", "-salt", "-in", file_path, "-out", decrypted_filename, "-pass", f"pass:{key_value}"],
                            capture_output=True, text=True, check=True
                        ) 
                    elif algorithm == "DES":
                        result = subprocess.run(
                            ["openssl", "enc", "-des-cbc", "-d", "-provider", "legacy", "-provider", "default", "-salt", "-in", file_path, "-out", decrypted_filename, "-pass", f"pass:{key_value}"],
                            capture_output=True, text=True, check=True
                        )
                    else:
                        messagebox.showerror("Eroare", "Algoritm de decriptare necunoscut!")
                        return
                elif framework == "WINDOWSCND":
                    if algorithm == "AES":
                        return
                    elif algorithm == "DES":
                        return
                    else:
                        messagebox.showerror("Eroare", "Algoritm de decriptare necunoscut!")
                        return
                    
                    ps_script = f"""
                    # Extract private key from the key_value
                    $key_parts = '{key_value}'.Split('###KEY_SEPARATOR###')
                    $PrivateKey = $key_parts[0]  # Private key will be the first part
                    $PublicKey = $key_parts[1]   # Public key will be the second part (though not needed for decryption)

                    # Convert the private key to SecureString
                    $PrivateKey = ConvertTo-SecureString -String $PrivateKey -AsPlainText -Force

                    # Convert SecureString to Byte array
                    $PrivateKeyBytes = [System.Text.Encoding]::UTF8.GetBytes($PrivateKey)

                    # Read the encrypted file and extract the IV and ciphertext
                    $InputFile = '{file_path}'
                    $OutputFile = '{decrypted_filename}'

                    $FileBytes = [System.IO.File]::ReadAllBytes($InputFile)
                    $IV = $FileBytes[0..15]  # Extract the IV from the first 16 bytes
                    $CipherText = $FileBytes[16..($FileBytes.Length - 1)]  # The remaining bytes are the encrypted data

                    # Set up AES decryption
                    $AES = New-Object System.Security.Cryptography.AesManaged
                    $AES.Key = $PrivateKeyBytes  # Use the private key (converted to byte array)
                    $AES.IV = $IV
                    $AES.Mode = [System.Security.Cryptography.CipherMode]::CBC
                    $AES.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
                    $Decryptor = $AES.CreateDecryptor()

                    # Decrypt the ciphertext
                    $DecryptedData = $Decryptor.TransformFinalBlock($CipherText, 0, $CipherText.Length)

                    # Write the decrypted data to the output file
                    [System.IO.File]::WriteAllBytes($OutputFile, $DecryptedData)
                    """

                    try:
                        subprocess.run(["powershell", "-Command", ps_script], check=True)
                    except subprocess.CalledProcessError as e:
                        messagebox.showerror("Eroare PowerShell", f"Eroare la decriptarea fisierului: {e.stderr}")
                        print(e.stderr)
                        return
                else:
                    raise ValueError("Framework neimplementat.")
            else:
                raise ValueError("Operatie neimplementata.")
        except subprocess.CalledProcessError as e:
            messagebox.showerror("Eroare OpenSSL", f"Eroare la criptarea fisierului: {e.stderr}")
            print(e.stderr)
            return
        except Exception as e:
            messagebox.showerror("Eroare", f"A aparut o eroare la {selected_operation}a fisierului:\n{e}")
            return
            
    end_time = time.time()
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    file_id = create_file(file_path, filenameBD, f"{algorithm} - {framework}", key_id, selected_operation)
    execution_time = (end_time - start_time) * 1000  # Convertire in milisecunde
    memory_usage = peak / 1024  # Convertire in KB
    execution_time_per_bit = execution_time/total_bits
    memory_usage_per_bit = memory_usage/total_bits
    
    log_performance(selected_operation, selected_key, execution_time,execution_time_per_bit, memory_usage,memory_usage_per_bit, file_path)
   
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
            file.id, file.filename, file.encrypted_filename, file.operation, file.encryption_algorithm, file.key_id, file.created_at
        ))

def refresh_performance_logs():
    tree.delete(*tree.get_children())
    logs = get_performance_logs()
    for log in logs:
        tree.insert("", "end", values=(log.id, log.operation, log.algorithm, log.fisier, log.execution_time, log.execution_time_per_bit, log.memory_usage, log.memory_usage_per_bit))

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

key_list = ttk.Treeview(key_frame, columns=("ID", "Tip", "Algoritm", "Cheie", "Creat"), show="headings")
key_list.grid(row=2, column=0, columnspan=6, sticky="nsew")

key_list.heading("ID", text="ID")
key_list.heading("Tip", text="Tip")
key_list.heading("Algoritm", text="Algoritm")
key_list.heading("Cheie", text="Cheie")
key_list.heading("Creat", text="Creat la")

key_list.column("ID", stretch=tk.NO, width=50)  
key_list.column("Tip", stretch=tk.NO, width=125)  
key_list.column("Algoritm", stretch=tk.NO, width=150)  
key_list.column("Cheie", stretch=tk.NO,width=550) 
key_list.column("Creat", stretch=tk.NO,width=200)  

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

# Selectare tip operatie criptare/decriptare
tk.Label(file_frame, text="Operatie:").grid(row=0, column=5, padx=5)
operatie_var = tk.StringVar()
operatie_dropdown = ttk.Combobox(file_frame, textvariable=operatie_var, state="readonly")
operatie_dropdown.grid(row=0, column=6, padx=5)
operatie_dropdown['values'] = TIPMETODA

# Buton salvare fișier
save_file_button = tk.Button(file_frame, text="Salvează fisier", command=save_selected_file).grid(row=0, column=7, padx=5)
delete_file_button = tk.Button(file_frame, text="Sterge fisier", command=delete_selected_file).grid(row=0, column=8, padx=5)


# Listă fișiere
tk.Label(file_frame, text="Fisiere salvate:").grid(row=1, column=0, columnspan=6)

file_list = ttk.Treeview(file_frame, columns=("ID", "Nume", "Fisier Rezultat", "Operatie", "Algoritm", "Cheie ID", "Creat"), show="headings")
file_list.grid(row=2, column=0, columnspan=9, sticky="nsew")

file_list.heading("ID", text="ID")
file_list.heading("Nume", text="Nume Fisier")
file_list.heading("Fisier Rezultat", text="Fisier Rezultat")
file_list.heading("Operatie", text="Operatie")
file_list.heading("Algoritm", text="Algoritm")
file_list.heading("Cheie ID", text="ID Cheie")
file_list.heading("Creat", text="Creat la")

file_list.column("ID", stretch=tk.NO, width=50)  
file_list.column("Nume", stretch=tk.YES)  
file_list.column("Fisier Rezultat", stretch=tk.YES)  
file_list.column("Operatie", stretch=tk.YES)  
file_list.column("Algoritm", stretch=tk.YES) 
file_list.column("Cheie ID", stretch=tk.YES)  
file_list.column("Creat", stretch=tk.YES) 

# Asigura ca tabelul se ajustează corect
file_frame.grid_columnconfigure(1, weight=1)
file_frame.grid_rowconfigure(2, weight=1)

refresh_files()

# Tab Performanta
performance_tab = ttk.Frame(notebook)
notebook.add(performance_tab, text="Performanta")

delete_log_button = tk.Button(performance_tab, text="Sterge Performanta", command=delete_selected_performance_log)
delete_log_button.grid(row=0, column=0, padx=5, pady=5)

# Tabel Performance Logs
tree = ttk.Treeview(performance_tab, columns=("ID", "Operatie", "Algoritm", "Fisier", "Timp", "Timp per bit", "Memorie", "Memorie per bit"), show="headings")
tree.grid(row=2, column=0, columnspan=8, sticky="nsew")
tree.heading("ID", text="ID")
tree.heading("Operatie", text="Operatie")
tree.heading("Algoritm", text="Algoritm")
tree.heading("Fisier", text="Fisier")
tree.heading("Timp", text="Timp (ms)")
tree.heading("Timp per bit", text="Timp per bit (ms)")
tree.heading("Memorie", text="Memorie (KB)")
tree.heading("Memorie per bit", text="Memorie pet bit (KB)")


tree.column("ID", stretch=tk.NO, width=50)  
tree.column("Operatie", stretch=tk.YES, width=75)  
tree.column("Algoritm", stretch=tk.YES)
tree.column("Fisier", stretch=tk.YES)  
tree.column("Timp", stretch=tk.YES, width=150) 
tree.column("Timp per bit", stretch=tk.YES, width=150)  
tree.column("Memorie", stretch=tk.YES, width=150)
tree.column("Memorie per bit", stretch=tk.YES, width=150)


performance_tab.grid_columnconfigure(0, weight=1)
performance_tab.grid_rowconfigure(2, weight=1)

refresh_performance_logs()

root.mainloop()