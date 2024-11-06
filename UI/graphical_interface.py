from tkinter import *
from tkinter import ttk
from pathlib import Path
from cryptography_func import asimetricno

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
            # input_file_text['state'] = 'enabled'
            # input_file_text.replace('1.0', 'end', filepath.read_text())
            input_file_text.set(filepath.read_text())
            # input_file_text['state'] = 'disabled'
        except Exception as e:
            print("failed to read input from file!")
   
    else:
        print("no file found!!")

def runAllFunctions():
    [private_key_path, public_key_path] = asimetricno.generate_exchange_keys()
    public_key_text.set(public_key_path.read_text())
    private_key_text.set(private_key_path.read_text())
    pass



root = Tk()
root.title("Napredni OS Projektni Zadatak")

# content frame
mainframe = ttk.Frame(root, padding="3 3 12 12")
mainframe.grid(column=0, row=0, sticky=(N, W, E, S))
root.columnconfigure(0, weight=1)
root.rowconfigure(0, weight=1)

# entry widget

content_to_write = StringVar()
content_entry = ttk.Entry(mainframe, width=64, textvariable=content_to_write)

ttk.Button(mainframe, text = "Write to input file", command=writeToInputTextFile)
ttk.Label(mainframe, text="Content of input_file.txt:")

input_file_text = StringVar()
ttk.Label(mainframe, textvariable=input_file_text)
# input_file_text = Text(mainframe, width=64, height=1)
# input_file_text['state'] = 'disabled'

ttk.Button(mainframe, text = "Run")

ttk.Label(mainframe, text="Asimetrično: RSA")
ttk.Label(mainframe, text="javni_kljuc.txt")
public_key_text = StringVar()
ttk.Label(mainframe, textvariable=public_key_text)

ttk.Label(mainframe, text="privatni_kljuc.txt")
private_key_text = StringVar()
ttk.Label(mainframe, textvariable=private_key_text)


for child in mainframe.winfo_children(): 
    child.grid_configure(padx=5, pady=5)


root.mainloop()