from tkinter import *
from tkinter import ttk
from pathlib import Path
import customtkinter
import sys
sys.path.append(str(Path(__file__).parent.parent)) 
from cryptography_func import asimetricno
from cryptography_func import simetricno


def writeToInputTextFile():
    #args: file, what to write
    text = content_entry.get()
    filepath= Path("files/input_file.txt")
    if (text == ""):
        print("nothing in text")
        return
    
    try:
        filepath.write_text(text)
        readFromInputTextFile()
        
    except Exception as e:
        print("failed to write to file")

def readFromInputTextFile():
    filepath = Path("files/input_file.txt")
    if filepath.exists():
        print("file found!")
        
        try:
            input_file_textbox['state'] = 'normal'
            input_file_textbox.replace('1.0', 'end', filepath.read_text())
            input_file_textbox['state'] = 'disabled'

        except Exception as e:
            print("failed to read input from file!")
   
    else:
        print("no file found!!")

def runAllFunctions():
    print("running all functions")
    # asimetricno
    private_key_path, public_key_path = asimetricno.generate_exchange_keys()
    public_key_text.set(public_key_path.read_text())
    
    public_key_textbox['state'] = 'normal'
    public_key_textbox.replace('1.0', 'end', public_key_path.read_text())
    public_key_textbox['state'] = 'disabled'
    
    private_key_textbox['state'] = 'normal'
    private_key_textbox.replace('1.0', 'end', private_key_path.read_text())
    private_key_textbox['state'] = 'disabled'
    
    # simetricno
    secret_key_path = simetricno.generate_secret_key()
    secret_key_textbox['state'] = 'normal'
    secret_key_textbox.replace('1.0', 'end', secret_key_path.read_text())
    secret_key_textbox['state'] = 'disabled'
    pass

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


root.columnconfigure(0, weight=1)
root.rowconfigure(0, weight=1)


first_frame = ttk.Frame(mainframe)
first_frame.grid(column=0, row=0, sticky=(W, E))  # Ensure first_frame is placed properly

second_frame = ttk.Frame(mainframe)
second_frame.grid(column=1)


content_to_write = StringVar()
content_entry = ttk.Entry(first_frame, width=64, textvariable=content_to_write)
content_entry.grid(column=0, row=0, padx=5, pady=5)


write_button = ttk.Button(first_frame, text="Write to input file", command=writeToInputTextFile)
write_button.grid(column=1, row=0, padx=5, pady=5)
ttk.Label(first_frame, text="Content of input_file.txt:").grid(column=0, row=1, padx=5, pady=5, columnspan=2)


input_file_textbox = Text(first_frame, height=5, width=64, borderwidth=1.0, relief="sunken", state="disabled")
input_file_textbox.grid(column=0, row=2, columnspan=2, padx=5, pady=5)
# input_file_text = Text(mainframe, width=64, height=1)
# input_file_text['state'] = 'disabled'

ttk.Button(mainframe, text = "Run", command=runAllFunctions)

ttk.Label(mainframe, text="Asimetrično: RSA")

ttk.Label(mainframe, text="javni_kljuc.txt")
public_key_text = StringVar()

public_key_textbox = Text(
    mainframe, height=10, borderwidth=1.0,
    relief=SUNKEN,state=DISABLED, width=64, wrap="none" )


ttk.Label(mainframe, text="privatni_kljuc.txt")
private_key_text = StringVar()



private_key_textbox = Text(
    mainframe, height=10, borderwidth=1.0,
    relief=SUNKEN, state=DISABLED, width=64, wrap="none" )
ys = ttk.Scrollbar(mainframe, orient='vertical', command=private_key_textbox.yview)
private_key_textbox['yscrollcommand'] = ys.set

ttk.Label(mainframe, text="tajni_kljuc.txt (HEX format)",)
secret_key_text = StringVar()


secret_key_textbox = Text(
    mainframe, height=1, borderwidth=1.0,
    relief=SUNKEN,state=DISABLED, width=64, wrap="none" )

ttk.Label(mainframe, text="Enkriptirani tekst asimetricno:")



for child in mainframe.winfo_children(): 
    child.grid_configure(padx=3, pady=3)

app = App()
app.mainloop()

root.mainloop()
