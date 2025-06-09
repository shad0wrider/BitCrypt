#This is BitCrypt v5 gui
#By https://github.com/shad0wrider
#Can encrypt small to large files efficiently and securely



from customtkinter import *
import os , time , sys , multiprocessing as mproc , subprocess as sp
import socket , secrets , math , sys
from subprocess import CalledProcessError,CompletedProcess
from PIL import Image
from cryptcorev5 import enc,dec



app = CTk()

prevprog = 0

try:
    
    sys.stderr = open(os.devnull,"w")
 
    app.wm_title("BitCrypt")
    app.minsize(650,550)
    app.geometry("650x550")
    set_appearance_mode('system')

    blackmoon = Image.open("/home/electro/Downloads/blackmoon.png")
    whitesun = Image.open("/home/electro/Downloads/whitesun3.png")
    theverdict = StringVar()

    def setverdictyes():
        theverdict.set("0")

    def setverdictno():
        theverdict.set("1")

    def returnhome():
        progressframe.destroy()
        app.update()
        homepage()

    def cancelreturn():
        encproc.terminate()
        returnhome()
    
    def toggle():
        if get_appearance_mode() == "Light":
            togbtn.configure(fg_color="transparent")
            set_appearance_mode('Dark')
        elif get_appearance_mode() =="Dark":
            togbtn.configure(fg_color="transparent")
            set_appearance_mode('Light')
          
    
    def decpasstoggle():
        if decogpass.cget("show") =="*":
                decogpass.configure(show="")
                dechideshowbtn.configure(text="Hide Password")
        elif decogpass.cget("show") =="":
                decogpass.configure(show="*")
                dechideshowbtn.configure(text="Show Password")


    

    def passtoggle():
        if ogpass.cget("show") =="*":
                ogpass.configure(show="")
                confirmpass.configure(show="")
                hideshowbtn.configure(text="Hide Passwords")
        elif ogpass.cget("show") =="":
                ogpass.configure(show="*")
                confirmpass.configure(show="*")
                hideshowbtn.configure(text="Show Passwords")

    def rewindow():
        window.destroy()
        app.update()
        return confirmwindow()

    def rehome():
        errorbox.destroy()
        progressframe.destroy()
        app.update()
        return homepage()

    def confirmwindow():
        global window
        window = CTkToplevel()
        window.wm_title("Confirm Password")
        window.minsize(300,300)
        yesbtn = CTkButton(master=window,width=250,height=40,text="Yes,use this Password",command=setverdictyes)
        yesbtn.place(relx=0.5,rely=0.2,anchor='n')
        nobtn = CTkButton(master=window,width=250,height=40,text="No,Change Password",command=setverdictno)
        nobtn.place(relx=0.5,rely=0.4,anchor='n')
        window.protocol('WM_DELETE_WINDOW',rewindow)
        window.wait_variable(theverdict)
        
        if theverdict.get() =="0":
            return 0
        elif theverdict.get() =="1":
            return 1
        
    def errorwindow(errorval:str):
        global errorbox
        os.remove(os.path.abspath(ipcfile))
        encproc.kill()
        errorbox = CTkToplevel()
        errorbox.focus()
        errorbox.wm_title("Error Occured")
        errorbox.geometry("200x200")
        errorlabel = CTkLabel(master=errorbox,width=100,height=50,text=errorval,text_color="red",font=CTkFont(size=19))
        errorlabel.place(relx=0.5,rely=0.3,anchor="n")
        errorbtn = CTkButton(master=errorbox,width=70,height=50,corner_radius=23,command=rehome,text="ok",font=CTkFont(size=23))
        errorbtn.place(relx=0.5,rely=0.5,anchor='n')
        app.update()
    
    def decerrorwindow(error:str):
       def killit():
              errorit.destroy()
              
       errorit = CTkToplevel()
       errorit.wm_title("Error Occured")
       fonter = CTkFont(size=21,family="Arial").measure(error)
       errorit.pack_propagate(True)
       theerror = CTkLabel(master=errorit,width=int(fonter),height=30,font=CTkFont(size=20),text=error,text_color="white",bg_color="red",corner_radius=21)
       therrorbtn = CTkButton(master=errorit, width=120,height=20,font=CTkFont(size=19),text="Ok",corner_radius=19,command=killit)
       theerror.pack(padx=20,pady=40,anchor='n')
       therrorbtn.pack(padx=20,pady=20,anchor='n')
       theerror.configure(text=str(error))

    def notify(alert:str):
       def killit():
              notifyit.destroy()              
       notifyit = CTkToplevel()
       notifyit.wm_title("Notify")
       fonter = CTkFont(size=21,family="Arial").measure(alert)
       notifyit.pack_propagate(True)
       theerror = CTkLabel(master=notifyit,width=int(fonter),height=30,font=CTkFont(size=20),text=alert,text_color="green",bg_color="transparent",corner_radius=21)
       therrorbtn = CTkButton(master=notifyit, width=120,height=20,font=CTkFont(size=19),text="Ok",corner_radius=19,command=killit)
       theerror.pack(padx=20,pady=40,anchor='n')
       therrorbtn.pack(padx=20,pady=20,anchor='n')
       theerror.configure(text=str(alert))


    # def decaskpass():
    #     def gibpass():
    #             decryptit.destroy()
    #     global decpassframe , decogpass , dechideshowbtn , decryptit
    #     decpassframe = CTkFrame(master=app,width=350,height=350,bg_color="transparent",corner_radius=15)
    #     decpassframe.place(relx=0.5,rely=0.5,anchor="center")
    #     decogpass = CTkEntry(master=decpassframe,width=250,height=40,bg_color="transparent",placeholder_text="Enter Password",show="*")
    #     decogpass.place(relx=0.5,rely=0.2,anchor="n")
    #     dechideshowbtn = CTkButton(master=decpassframe,height=30,width=70,text="Show Password",corner_radius=23,command=decpasstoggle)
    #     dechideshowbtn.place(relx=0.5,rely=0.6,anchor="n")
    #     decryptit = CTkButton(master=decpassframe,height=40,width=80,text="Decrypt",corner_radius=23,command=gibpass)
    #     decryptit.place(relx=0.5,rely=0.7,anchor='n')
    #     app.update()
    #     decryptit.wait_window()
    #     return decogpass.get()
        

    def askpass():
        global ogpass,confirmpass,infolabel,passframe,hideshowbtn
        passframe = CTkFrame(master=app,width=350,height=350,bg_color="transparent",corner_radius=15)
        passframe.place(relx=0.5,rely=0.5,anchor="center")
        ogpass = CTkEntry(master=passframe,width=250,height=40,bg_color="transparent",placeholder_text="Enter Password",show="*")
        ogpass.place(relx=0.5,rely=0.2,anchor="n")
        confirmpass = CTkEntry(master=passframe,width=250,height=40,bg_color="transparent",placeholder_text="Confirm Password",show="*")
        confirmpass.place(relx=0.5,rely=0.4,anchor="n")
        hideshowbtn = CTkButton(master=passframe,height=30,width=70,text="Show Passwords",corner_radius=23,command=passtoggle)
        hideshowbtn.place(relx=0.5,rely=0.6,anchor="n")
        infolabel = CTkLabel(master=passframe,width=200,height=40,bg_color="transparent")
        infolabel.place(relx=0.5,rely=0.7,anchor="n")
        app.update()
        while True:
            app.update()
            pass1,pass2 = ogpass.get() , confirmpass.get()
            if len(pass1) <= 0 or len(pass1) < 6:
                if get_appearance_mode() =="Dark":
                    infolabel.configure(text="Password Must be 6+ Characters",text_color="white")
                elif get_appearance_mode() =="Light":
                    infolabel.configure(text="Password Must be 6+ Characters",text_color="black")                
                app.update()
            elif pass1 == pass2 and len(pass1) >= 6:
                infolabel.configure(text="Passwords Match",text_color="green")
                app.update()
                break
            elif len(pass1) >= 6 and len(pass2) ==0:
                infolabel.configure(text="Please Confirm Password",text_color="yellow")
                app.update()
            elif pass1 != pass2 and len(pass2) > 2:
                infolabel.configure(text="Passwords Don't match",text_color="red")
                app.update()
            else:
                app.update()
        tmpval =  confirmwindow()
        if tmpval ==0:
            window.destroy()
            return ogpass.get()
        elif tmpval ==1:
            window.destroy()
            return askpass()
        



    def progressui(srcfile,ipc):
        global progressframe,progpercent , progressbar , prevprog
        passframe.destroy()
        progressframe = CTkFrame(master=app,width=340+20,height=150,bg_color="transparent",corner_radius=23)
        progressframe.place(relx=0.5,rely=0.3,anchor='n')
        progressframe.columnconfigure(index=0,weight=1)
        progressframe.rowconfigure(index=0,weight=1)
        label1 = CTkLabel(master=progressframe,width=100,height=50,text="Encrypting File...",font=CTkFont(size=23))
        label1.grid(column=0,row=0,padx=50)
        label2 = CTkLabel(master=progressframe,width=CTkFont("Arial",size=16).measure(srcfile),height=65,font=CTkFont(size=16),text=srcfile,wraplength=320)
        label2.grid(column=0,row=1,padx=50)
        progpercent = CTkLabel(master=progressframe,width=75,height=75,text="",font=CTkFont(size=23))
        progpercent.grid(column=0,row=2,padx=50)
        progressbar = CTkProgressBar(master=progressframe,width=200,height=15,corner_radius=23,orientation="horizontal")
        progressbar.grid(column=0,row=3,padx=20,pady=20)
        donebtn = CTkButton(master=progressframe,width=150,height=40,text="Done",font=CTkFont(size=21),bg_color="transparent",corner_radius=23,command=returnhome)
        cancelbtn = CTkButton(master=progressframe,width=150,height=40,text="Cancel",font=CTkFont(size=21),bg_color="transparent",corner_radius=23,command=cancelreturn)
        cancelbtn.grid(column=0,row=4,padx=20,pady=20)
        app.update()
        while True:
            progress , addr = ipc.recvfrom(1000)
            if b"%" in progress:
                tmpbar = progress.decode('utf-8').replace("info:","").replace("%","")[:4]
                if str(tmpbar) != prevprog: #This does frontend UI filtering preventing the GUI from processing same progress updates every milisecond
                    prevprog = str(tmpbar)
                    progpercent.configure(text=f"{tmpbar}%")
                    if tmpbar.split(".")[0] =="":
                        progressbar.set(tmpbar/10000)
                        app.update()
                    elif len(tmpbar.split(".")[0]) ==1:
                        progressbar.set(float(tmpbar)/100)
                        app.update()
                    elif len(tmpbar.split(".")[0]) ==2:
                        progressbar.set(float(tmpbar)/100)                
                        app.update()

            elif b'error:' in progress:
                processerror = progress.decode("utf-8").replace("error:","")
                errorwindow(processerror)
                break

            elif b'done:' in progress:
                progpercent.configure(text=f"100%")
                progressbar.set(1)
                app.update()
                notify(progress.decode("utf-8").replace("done:",""))
                break
        cancelbtn.grid_forget()
        donebtn.grid(column=0,row=4,padx=20,pady=20)
        app.update()
                

    def encprocess(filepath,passwd,folderpath):
        global encproc , ipcfile
        ipcfile = f"/tmp/{secrets.token_hex(4)+".socket"}"
        ipctalk = socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM)
        ipctalk.bind(ipcfile)
        encproc = mproc.Process(target=enc,args=((filepath),(passwd),(ipcfile),(folderpath),))
        encproc.daemon = False
        encproc.start()
        progressui(filepath,ipctalk)

    def decprogressui(ipc):
       global prevprog , decpassframe
       def decdone():
            decpassframe.destroy()
            homepage()
       progpercent = CTkLabel(master=decpassframe,width=150,height=20,font=CTkFont(size=22),text="0")
       progpercent.place(relx=0.5,rely=0.5,anchor='n')
       progressbar = CTkProgressBar(master=decpassframe,width=150,height=15,corner_radius=21)
       progressbar.place(relx=0.5,rely=0.7,anchor='n')
       donedecbtn = CTkButton(master=decpassframe,width=150,height=40,text="Done",corner_radius=23,font=CTkFont(size=21),command=decdone)
       app.update()
       while True:
             msg , addr = ipc.recvfrom(1000)
             k = msg.decode('utf-8')
             if "%" in k:
                tmpbar = k.replace("info:","").replace("%","")[:4]
                if str(tmpbar) != prevprog:
                     prevprog = str(tmpbar)
                     progpercent.configure(text=f"{str(tmpbar)}%")
                     if tmpbar.split(".")[0] =="":
                            progressbar.set(tmpbar/10000)
                            app.update()
                     elif len(tmpbar.split(".")[0]) ==1:
                            progressbar.set(float(tmpbar)/100)
                            app.update()
                     elif len(tmpbar.split(".")[0]) ==2:
                            progressbar.set(float(tmpbar)/100)                
                            app.update()
             if "error:" in k:
                    decerrorwindow(str(k.replace("error:","")))
                    decproc.kill()                    
                    break
             if "done:" in k:
                    progpercent.configure(text=f"{str(100)}%")
                    app.update()
                    notify(str(k.replace("done:","")))
                    break
       donedecbtn.place(relx=0.5,rely=0.8,anchor='n')

    def decprocess(srcfile:str,passw:str,folderpath:str):
        global decproc , decpassframe , decogpass , decryptbtn , infoit
        s = socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM)
        socfile = f"/tmp/{secrets.token_hex(4)}.socket"
        s.bind(socfile)
        decproc = mproc.Process(target=dec,args=((srcfile),(passw),(socfile),(folderpath),))
        decproc.daemon = True
        decproc.start()
        while True:
                msg , addr = s.recvfrom(1000)
                k = msg.decode('utf-8')
                if "error:Wrong Password" in k:
                        dechideshowbtn.place_forget()
                        infoit = CTkLabel(master=decpassframe,width=250,height=30,text="Wrong Password Entered",text_color="red",font=CTkFont(size=16))
                        infoit.place(relx=0.5,rely=0.7,anchor="n")
                        app.update()
                        time.sleep(2)
                        decproc.kill()
                        break
                elif "info:Correct Password Entered" in k:
                        dechideshowbtn.place_forget()
                        infoit = CTkLabel(master=decpassframe,width=250,height=30,text="Correct Password Entered",text_color="green",font=CTkFont(size=16))
                        infoit.place(relx=0.5,rely=0.7,anchor="n")
                        app.update()
                        time.sleep(2)
                        break
        infoit.place_forget()
        decogpass.place_forget()
        app.update()
        if "info:Correct Password Entered" in k:
                decryptbtn.place_forget()
                decprogressui(s)
        if "error:Wrong Password" in k:
                decpassframe.destroy()
                homepage()

    def doenc():
        mainframe.destroy()
        header.configure(text="Encryption Mode")
        app.update()
        try:
            tmpfile = sp.check_output("zenity --file-selection --filename='' --title 'Select File To Encrypt'",shell=True,stderr=open(os.devnull,"w"))
        except CalledProcessError as ke:
            print("File fetch error")
            return homepage()
        
        try:
            tmpsavefolder = sp.check_output('zenity --file-selection --directory --title="Select Folder to Save Encrypted File In"',shell=True,stderr=open(os.devnull,"w"))
        except CalledProcessError as ek:
            print("Folder save error")
            return homepage()
        
        filetoenc = tmpfile.decode("utf-8").replace("\n","")
        filetofolder = tmpsavefolder.decode("utf-8").replace("\n","")

        tmpfilepass = askpass()
        if tmpfilepass:
            doencbtn = CTkButton(master=passframe,width=250,height=50,text="Encrypt File",font=CTkFont(size=23),corner_radius=32,hover_color="green",command=lambda:encprocess(filetoenc,tmpfilepass,filetofolder))
            infolabel.destroy()
            doencbtn.place(relx=0.5,rely=0.75,anchor='n')
    
    def dodec():
        mainframe.destroy()
        header.configure(text="Decryption Mode")
        app.update()
        global decpassframe , decogpass , dechideshowbtn , decryptbtn
        try:
                tmpfile = sp.check_output("zenity --file-selection --filename='' --title 'Select File To Decrypt'",shell=True,stderr=open(os.devnull,"w"))
        except CalledProcessError as ke:
                return homepage()
        
        try:
                tmpsavefolder = sp.check_output('zenity --file-selection --directory --title="Select Folder to Save Decrypted File In"',shell=True,stderr=open(os.devnull,"w"))
        except CalledProcessError as ek:
                return homepage()
        
        filetodec = tmpfile.decode("utf-8").replace("\n","")
        filetofolder = tmpsavefolder.decode("utf-8").replace("\n","")

        decpassframe = CTkFrame(master=app,width=350,height=430,bg_color="transparent",corner_radius=21)
        header.grid_forget()
        decpassframe.place(relx=0.5,rely=0.5,anchor="center")
        declabel = CTkLabel(master=decpassframe,width=250,height=40,font=CTkFont(size=23),text="Decrypting File...")
        declabel.place(relx=0.5,rely=0.1,anchor='n')
        decfilelabel = CTkLabel(master=decpassframe,width=CTkFont(size=21).measure(filetodec),text=f"{filetodec}",height=50,font=CTkFont(size=21),wraplength=320)
        decfilelabel.place(relx=0.5,rely=0.3,anchor='n')
        decogpass = CTkEntry(master=decpassframe,width=250,height=40,bg_color="transparent",placeholder_text="Enter Password",show="*")
        decogpass.place(relx=0.5,rely=0.5,anchor="n")
        dechideshowbtn = CTkButton(master=decpassframe,height=20,width=70,text="Show Password",corner_radius=23,command=decpasstoggle)
        dechideshowbtn.place(relx=0.5,rely=0.7,anchor="n")
        decryptbtn = CTkButton(master=decpassframe,width=150,height=40,text="Decrypt",corner_radius=23,font=CTkFont(size=21),command=lambda:decprocess(filetodec,decogpass.get(),filetofolder))
        decryptbtn.place(relx=0.5,rely=0.8,anchor='n')
        app.update()

                

    def homepage():
        global togbtn,mainframe,encbtn,decbtn,header

        header = CTkLabel(master=app,width=200,height=50,text="BitCrypt",font=CTkFont(size=23),corner_radius=15)
        app.grid_columnconfigure(0, weight=1)
        header.grid(column=0,row=0,padx=40,pady=30,sticky="ew")

        mainframe = CTkFrame(master=app,width=100,height=250,corner_radius=15,bg_color="transparent")
        mainframe.grid(column=0,row=4,padx=60,pady=100,sticky="ew")
        mainframe.grid_columnconfigure(2,weight=1)
        mainframe.grid_rowconfigure(0,weight=1)

        togbtn = CTkButton(width=30,height=30,master=app,text=None,bg_color="transparent",fg_color="transparent",command=toggle,corner_radius=32,image=CTkImage(dark_image=whitesun,size=(110,70),light_image=blackmoon))
        togbtn.grid(column=1,row=0,padx=10,pady=10,sticky="ew")

        encbtn = CTkButton(width=50,height=50,master=mainframe,text="Encrypt",text_color="white",command=doenc,font=CTkFont(size=23),corner_radius=15,anchor="center")
        encbtn.grid(column=2,row=1,padx=10,pady=10,sticky="ew",ipadx=10)
        decbtn = CTkButton(width=50,height=50,master=mainframe,text="Decrypt",text_color="white",command=dodec,font=CTkFont(size=23),corner_radius=15,anchor="center")
        decbtn.grid(column=2,row=2,padx=10,pady=10,sticky="ew",ipadx=20)


        


    homepage()
except Exception as ee:
    print(ee)
    errorwindow(ee)



app.mainloop()
