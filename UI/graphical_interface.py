from tkinter import *
from tkinter import ttk
from tkinter import filedialog
from pathlib import Path

from tkinter import font

import sys
sys.path.append(str(Path(__file__).parent.parent)) 
from cryptography_func import asimetricno
from cryptography_func import simetricno
from cryptography_func import potpis_sazetak

main_file : Path = Path("")

def updateMainFileInUse(filepath : Path):
   global main_file
   main_file = filepath

def checkIfMainFileInUseExists() -> bool:
    print("filepath exists : ", main_file.is_file())
    return main_file.is_file()


def getInputTextFile():
    filepath = Path(filedialog.askopenfilename())
    
    if filepath.exists():
        print("file found!")
        updateMainFileInUse(filepath)
        try:
            input_file_textbox['state'] = 'normal'
            input_file_textbox.replace('1.0', 'end', filepath.read_text())
            input_file_textbox['state'] = 'disabled'

        except Exception as e:
            print("failed to read input from file!")
    else:
        print("no file found!!")

# ------------------------

def generateAndSaveSymmetricKey():
    print("generating and saving symmetric key")
    print("asking for save file name")
    secret_key_path = Path(filedialog.asksaveasfilename(title="Spremanje tajnog ključa...", defaultextension=".txt",filetypes=[("Text Files", "*.txt"),("All Files", "*.*")]))
        
    simetricno.generate_secret_key(secret_key_path)



def generateAndSaveAsymmetricKeys():
    print("generating and saving asymmetric keys")
    
    print("asking for save file name")
    private_key_path = Path(filedialog.asksaveasfilename(title="Spremanje privatnog ključa...", defaultextension=".txt",filetypes=[("Text Files", "*.txt"),("All Files", "*.*")]))
    public_key_path = Path(filedialog.asksaveasfilename(title="Spremanje javnog ključa...", defaultextension=".txt",filetypes=[("Text Files", "*.txt"),("All Files", "*.*")]))

        
    asimetricno.generate_exchange_keys(private_key_path, public_key_path)
        

def loadAsymmetricKeys():
    
    public_key_path = Path(filedialog.askopenfilename(title="Odaberite javni ključ..."))
    private_key_path = Path(filedialog.askopenfilename(title="Odabire privatni ključ..."))
    
    
    if public_key_path.is_file() and private_key_path.is_file():
        public_key_textbox['state'] = 'normal'
        public_key_textbox.replace('1.0', 'end', public_key_path.read_text())
        public_key_textbox['state'] = 'disabled'
            
        private_key_textbox['state'] = 'normal'
        private_key_textbox.replace('1.0', 'end', private_key_path.read_text())
        private_key_textbox['state'] = 'disabled'
    else:
        print("no files selected!")

def loadSymmetricKey():
    secret_key_path = Path(filedialog.askopenfilename(title="Odaberite tajni ključ..."))

    if secret_key_path.is_file():
        secret_key_textbox['state'] = 'normal'
        secret_key_textbox.replace('1.0', 'end', secret_key_path.read_bytes().hex())
        secret_key_textbox['state'] = 'disabled'
    else:
        print("no file selected!")

def encryptAsymmetric():
    if not main_file.is_file():
        print("no main file loaded!")
        return
    
    encrypted_asymmetric_path = Path(filedialog.asksaveasfilename(title="Spremanje enkriptiranog filea...", defaultextension=".txt",filetypes=[("Text Files", "*.txt"),("All Files", "*.*")]))

    if encrypted_asymmetric_path != "":
        public_key_path = Path(filedialog.askopenfilename(title="Odaberite javni ključ za enkripciju..."))
        if public_key_path.is_file():
            asimetricno.encrypt_asymmetric(main_file, encrypted_asymmetric_path, public_key_path)
            asymmetric_encrypted_textbox['state'] = 'normal'
            asymmetric_encrypted_textbox.replace('1.0', 'end', encrypted_asymmetric_path.read_bytes())
            asymmetric_encrypted_textbox['state'] = 'disabled'


def encryptSymmetric():
    if not main_file.is_file():
        print("no main file loaded!")
        return
    
    encrypted_symmetric_path = Path(filedialog.asksaveasfilename(title="Spremanje enkriptiranog filea...", defaultextension=".txt",filetypes=[("Text Files", "*.txt"),("All Files", "*.*")]))

    if encrypted_symmetric_path != "":
        secret_key_path = Path(filedialog.askopenfilename(title="Odaberite tajni ključ za enkripciju..."))
        if secret_key_path.is_file():
            simetricno.encrypt_symmetric(main_file, encrypted_symmetric_path, secret_key_path)
            
            symmetric_encrypted_textbox['state'] = 'normal'
            symmetric_encrypted_textbox.replace('1.0', 'end', encrypted_symmetric_path.read_bytes())
            symmetric_encrypted_textbox['state'] = 'disabled'
    else:
        print("no filepath defined!")
        return

def decryptAsymmetric():
    decrypted_asymmetric_path = Path(filedialog.askopenfilename(title="Otvaranje enkriptiranog filea..."))
    decrypted_asymmetric_save_path = Path(filedialog.asksaveasfilename(title="Spremanje dekriptiranog filea...", defaultextension=".txt",filetypes=[("Text Files", "*.txt"),("All Files", "*.*")]))

    if decrypted_asymmetric_path.is_file():
        private_key_path = Path(filedialog.askopenfilename(title="Odaberite privatni ključ za dekripciju..."))
        if private_key_path.is_file():
                asimetricno.decrypt_asymmetric(decrypted_asymmetric_path, decrypted_asymmetric_save_path, private_key_path)
                
                asymmetric_decrypted_textbox['state'] = 'normal'
                asymmetric_decrypted_textbox.replace('1.0', 'end', decrypted_asymmetric_save_path.read_text())
                asymmetric_decrypted_textbox['state'] = 'disabled'
    
    
def decryptSymmetric():
    decrypted_symmetric_path = Path(filedialog.askopenfilename(title="Otvaranje enkriptiranog filea..."))
    decrypted_symmetric_save_path = Path(filedialog.asksaveasfilename(title="Spremanje dekriptiranog filea...", defaultextension=".txt",filetypes=[("Text Files", "*.txt"),("All Files", "*.*")]))
    if decrypted_symmetric_path.is_file():
        secret_key_path = Path(filedialog.askopenfilename(title="Odaberite tajni ključ za dekripciju..."))
        if secret_key_path.is_file():
            simetricno.decrypt_symmetric(decrypted_symmetric_path, decrypted_symmetric_save_path, secret_key_path)
            
            symmetric_decrypted_textbox['state'] = 'normal'
            symmetric_decrypted_textbox.replace('1.0', 'end', decrypted_symmetric_save_path.read_text())
            symmetric_decrypted_textbox['state'] = 'disabled'

def calculateFileHash():
    if not main_file.is_file():
        print("no main file loaded!")
        return
    
    hash_save_path = Path(filedialog.asksaveasfilename(title="Spremanje hash filea...", defaultextension=".txt",filetypes=[("Text Files", "*.txt"),("All Files", "*.*")]))

    if hash_save_path != "":
        potpis_sazetak.calculate_file_hash(main_file, hash_save_path)
        
        hash_textbox['state'] = 'normal'
        hash_textbox.replace('1.0', 'end', hash_save_path.read_text())
        hash_textbox['state'] = 'disabled'

        print("should've saved!")
    else:
        print("no hash file location selected")

def createFileSignature():
    if not main_file.is_file():
        print("no main file loaded!")
        return

    signature_save_path = Path(filedialog.asksaveasfilename(title="Spremanje signature filea...", defaultextension=".txt",filetypes=[("Text Files", "*.txt"),("All Files", "*.*")]))

    if signature_save_path != "":
        private_key_path = Path(filedialog.askopenfilename(title="Odaberite privatni ključ za potpis..."))
        if private_key_path.is_file():
            potpis_sazetak.generate_digital_signature(main_file, private_key_path, signature_save_path)
            digital_signature_textbox['state'] = 'normal'
            digital_signature_textbox.replace('1.0', 'end', signature_save_path.read_bytes())
            digital_signature_textbox['state'] = 'disabled'


def checkDigitalSignature():
    file_to_check_path = Path(filedialog.askopenfilename(title="Odaberite izvornu datoteku..."))
    signature_path = Path(filedialog.askopenfilename(title="Odaberite datoteku potpisa..."))
    public_key_path = Path(filedialog.askopenfilename(title="Odaberite javni ključ..."))
    if file_to_check_path.is_file() and signature_path.is_file() and public_key_path.is_file():
        val = potpis_sazetak.check_digital_signature(file_to_check_path, signature_path, public_key_path)
        if val == True:
            is_valid.set("VALIDNA!")
            is_signature_valid_label.config(foreground="green")
        else:
            is_valid.set("NIJE VALIDNA!")
            is_signature_valid_label.config(foreground="red")
    else:
        print("no filepaths chosen!")
        return



# ------------------------------------------------------------


class InputFileFrame(customtkinter.CTkFrame):
    def __init__(self, master):
        super().__init__(master)
        
        self.naslov = customtkinter.CTkLabel(self, text="Input file", fg_color="gray30", corner_radius=5)
        self.naslov.grid(row=0, column=0)

class AsymmetricKeysFrame(customtkinter.CTkFrame):
    def __init__(self, master):
        super().__init__(master)
        self.naslov = customtkinter.CTkLabel(self, text="Asimetricni kljucevi", fg_color="gray30", corner_radius=5)
        self.naslov.grid(row=0, column=0)
        
        self.private_key_box = customtkinter.CTkTextbox(self, state='disabled')
        self.private_key_box.grid(row=1, column=0, pady=10, padx = 5)
        self.public_key_box = customtkinter.CTkTextbox(self, state='disabled')
        self.public_key_box.grid(row=1, column=1)
        
class SymmetricKeyFrame(customtkinter.CTkFrame):
    def __init__(self, master):
        super().__init__(master)
        
        self.naslov = customtkinter.CTkLabel(self, text="Simetrican kljuc", fg_color="gray30", corner_radius=5)
        self.naslov.grid(row=0, column=0)
        
        self.secret_key_box = customtkinter.CTkTextbox(self, state='disabled')
        self.secret_key_box.grid(row=1, column=0)


class HashSignatureFrame(customtkinter.CTkFrame):
    def __init__(self, master):
        super().__init__(master)
        self.naslov = customtkinter.CTkLabel(self, text="Hash", fg_color="gray30", corner_radius=5)
        self.naslov.grid(row=0, column=0)
        
        self.hash_box = customtkinter.CTkTextbox(self, state='disabled')
        self.hash_box.grid(row=1, column=0)

class DigitalSignatureFrame(customtkinter.CTkFrame):
    def __init__(self, master):
        super().__init__(master)
        self.naslov = customtkinter.CTkLabel(self, text="Potpis", fg_color="gray30", corner_radius=5)
        self.naslov.grid(row=0, column=0)
        
        self.digital_signature_box = customtkinter.CTkTextbox(self, state='disabled')
        self.digital_signature_box.grid(row=1, column=0)
        

class EncryptedSymmetricFrame(customtkinter.CTkFrame):
    def __init__(self, master):
        super().__init__(master)
        self.naslov = customtkinter.CTkLabel(self, text="Enkriptirano simetrično", fg_color="gray30", corner_radius=5)
        self.naslov.grid(row=0, column=0)
        
        self.encrypted_symmetric_box = customtkinter.CTkTextbox(self, state='disabled')
        self.encrypted_symmetric_box.grid(row=1, column=0)

class EncryptedAsymmetricFrame(customtkinter.CTkFrame):
    def __init__(self, master):
        super().__init__(master)
        self.naslov = customtkinter.CTkLabel(self, text="Enkriptirano asimetrično", fg_color="gray30", corner_radius=5)
        self.naslov.grid(row=0, column=0)
        
        self.encrypted_asymmetric_box = customtkinter.CTkTextbox(self, state='disabled')
        self.encrypted_asymmetric_box.grid(row=1, column=0)


class App(customtkinter.CTk):
    def __init__(self):
        super().__init__()

        self.title("Napredni OS Projektni Zadatak")
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)
        
        self.input_frame = InputFileFrame(self)
        self.input_frame.grid(row=0, column=0, padx=10, pady=10)
        
        self.asymmetric_keys_frame = AsymmetricKeysFrame(self)
        self.asymmetric_keys_frame.grid(row=1, column=0, padx= 10)

        self.symmetric_key_frame = SymmetricKeyFrame(self)
        self.symmetric_key_frame.grid(row=2, column=0, pady=10, padx=10)
        
        self.encrypted_asymmetric_frame = EncryptedAsymmetricFrame(self)
        self.encrypted_asymmetric_frame.grid(row=1, column=1)
        
        self.encrypted_symmetric_frame = EncryptedSymmetricFrame(self)
        self.encrypted_symmetric_frame.grid(row=2, column=1)
        
        self.hash_frame = HashSignatureFrame(self)
        self.hash_frame.grid(row=1, column=2, padx=10)
        
        self.signature_frame = DigitalSignatureFrame(self)
        self.signature_frame.grid(row=2, column=2)


root = Tk()
root.title("Napredni OS Projektni Zadatak")

# content frame
mainframe = ttk.Frame(root, padding="3 3 12 12")
mainframe.grid(column=0, row=0, sticky=(N, W, E, S))

first_column = ttk.Frame(mainframe, padding="3 3 12 12")
first_column.grid(row=0, column=0, sticky=(N, W, E, S))

second_column=ttk.Frame(mainframe, padding="3 3 12 12")
second_column.grid(row=0, column=1, sticky=(N, W, E, S))

third_column=ttk.Frame(mainframe, padding="3 3 12 12")
third_column.grid(row=0, column=2, sticky=(N, W, E, S))

root.columnconfigure(0, weight=1)
root.columnconfigure(1, weight=1)
root.columnconfigure(2, weight=0)
root.rowconfigure(0, weight=1)


loadInputFileButton = ttk.Button(first_column, text="Učitaj text file", command=getInputTextFile)


ttk.Label(first_column, text="Sadržaj učitanog file-a:")


input_file_textbox = Text(first_column, height=5, width=64, borderwidth=1.0, relief="sunken", state="disabled")

ttk.Label(first_column, text="Asimetrično: RSA")
generateAsymmetricKeyButton = ttk.Button(first_column, text="Generiraj i spremi asimetrične ključeve", command=generateAndSaveAsymmetricKeys)
loadAsymmetricKeysButton = ttk.Button(first_column, text="Učitaj asimetrične ključeve", command=loadAsymmetricKeys)
ttk.Label(first_column, text="Javni ključ")
public_key_text = StringVar()

public_key_textbox = Text(
    first_column, height=10, borderwidth=1.0,
    relief=SUNKEN,state=DISABLED, width=64, wrap="char" )


ttk.Label(first_column, text="Privatni ključ")
private_key_text = StringVar()

private_key_textbox = Text(
    first_column, height=10, borderwidth=1.0,
    relief=SUNKEN, state=DISABLED, width=64, wrap="char" )
# ys = ttk.Scrollbar(first_column, orient='vertical', command=private_key_textbox.yview)
# private_key_textbox['yscrollcommand'] = ys.set




# -------- JAVNI KLJUC ----------


ttk.Label(first_column, text="Simetrično: AES256")
generateSymmetricKeyButton = ttk.Button(first_column, text="Generiraj i spremi tajni ključ", command=generateAndSaveSymmetricKey)
loadSymmetricKeyButton = ttk.Button(first_column, text="Učitaj tajni ključ", command=loadSymmetricKey)
ttk.Label(first_column, text="Tajni ključ (HEX format)",)
secret_key_text = StringVar()

secret_key_textbox = Text(
    first_column, height=2, borderwidth=1.0,
    relief=SUNKEN,state=DISABLED, width=64, wrap="char" )







# ---------- ENKRIPCIJA ----------

ttk.Label(second_column, text="Enkripcija", font=font.BOLD)

ttk.Button(second_column, text="Enkriptiraj file simetrično", command=encryptSymmetric)

ttk.Label(second_column, text="Simetrično enkriptirano:")
symmetric_encrypted_textbox = Text(
    second_column, height=5, borderwidth=1.0,
    relief=SUNKEN,state=DISABLED, width=64, wrap="char" )

ttk.Button(second_column, text="Dekriptiraj file simetrično", command=decryptSymmetric)

ttk.Label(second_column, text="Simetrično dekriptirano:")
symmetric_decrypted_textbox = Text(
    second_column, height=5, borderwidth=1.0,
    relief=SUNKEN,state=DISABLED, width=64, wrap="char" )


ttk.Button(second_column, text="Enkriptiraj file asimetrično", command=encryptAsymmetric)

ttk.Label(second_column, text="Asimetrično enkriptirano:")
asymmetric_encrypted_textbox = Text(
    second_column, height=5, borderwidth=1.0,
    relief=SUNKEN,state=DISABLED, width=64, wrap="char" )

ttk.Button(second_column, text="Dekriptiraj file asimetrično", command=decryptAsymmetric)

ttk.Label(second_column, text="Asimetrično dekriptirano:")
asymmetric_decrypted_textbox = Text(
    second_column, height=5, borderwidth=1.0,
    relief=SUNKEN,state=DISABLED, width=64, wrap="char" )




# ----------- SAZETAK PORUKE ----------------
ttk.Label(third_column, text="Hash i signature", font=font.BOLD)

ttk.Button(third_column, text="Izračunaj hash ulaznog file-a", command=calculateFileHash)
hash_textbox = Text(
    third_column, height=5, borderwidth=1.0,
    relief=SUNKEN,state=DISABLED, width=64, wrap="char" )

ttk.Button(third_column, text="Generiraj digitalni potpis za file", command=createFileSignature)
digital_signature_textbox = Text(
    third_column, height=5, borderwidth=1.0,
    relief=SUNKEN,state=DISABLED, width=64, wrap="char" )

ttk.Button(third_column, text="Provjera potpisa", command=checkDigitalSignature)
is_valid = StringVar()
is_signature_valid_label = ttk.Label(third_column, text="Nije provjereno")
is_signature_valid_label['textvariable'] = is_valid
is_valid.set("Nije provjereno")

# ------ END ---------
for child in mainframe.winfo_children():
    for child in first_column.winfo_children():
        child.grid_configure(padx=3, pady=3)
    for child in second_column.winfo_children():
        child.grid_configure(padx=3, pady=3)
    for child in third_column.winfo_children():
            child.grid_configure(padx=3, pady=3)

app = App()
app.mainloop()

root.mainloop()
