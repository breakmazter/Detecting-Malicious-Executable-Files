import pickle
from tkinter import END, Text, ttk
from tkinter.filedialog import *
from ttkthemes import ThemedTk
import tkinter.font

import numpy as np

from extract_info import file_features


def open_file():
    filename = askopenfilename(parent=root)
    txt1.insert(END, filename)


def check_file():
    path = txt1.get("1.0", "end")
    data = file_features(path.strip())
    model = pickle.load(open("models/model.pkl", 'rb'))

    data_mass = np.array([list(data.values())])

    X_testing_scaled = model.named_steps['scale'].transform(data_mass)
    X_testing_pca = model.named_steps['pca'].transform(X_testing_scaled)
    percent_answer = model.named_steps['clf'].predict_proba(X_testing_pca)
    abs_answer = model.named_steps['clf'].predict(X_testing_pca)

    if abs_answer:
        s = f"Данная программа вредоносна с вероятностью {round(percent_answer[0][1]*100, 3)}%"
    else:
        s = f"Данная программа не вредоносна с вероятностью {round(percent_answer[0][0] * 100, 3)}%"

    txt2.insert(END, s)


def close_file():
    txt1.delete('1.0', END)
    txt2.delete('1.0', END)


root = ThemedTk(theme="black")
root["bg"] = "gray22"

root.title("AntiMalware")
root.geometry("750x600")
root.resizable(False, False)

# Menu
helv36 = tkinter.font.Font(family='Helvetica', size=19, weight='bold')

txt1 = Text(root, width=40, height=1)
txt1.place(x=190, y=530)

txt2 = Text(root, width=93, height=1, font=helv36)
txt2.place(x=1, y=0)

bt1 = ttk.Button(text="Check file",  command=check_file)
bt1.place(x=312, y=560)

bt2 = ttk.Button(text="Close", command=close_file)
bt2.place(x=412, y=560)

bt2 = ttk.Button(text="Open", command=open_file)
bt2.place(x=212, y=560)

root.mainloop()
