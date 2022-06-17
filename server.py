#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sat Jun  4 05:53:52 2022

@author: antonzubchenko
"""
import command_line_client

from flask import Flask, render_template, flash, request, redirect, url_for, send_from_directory
import os
from werkzeug.utils import secure_filename

APP_ROOT = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = './uploads'
ALLOWED_EXTENSIONS = {'txt'}

app = Flask(__name__)
app.secret_key = "key"
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER



@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)           


def allowed_file(filename):                                                     # checks if the extension is right
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
          

@app.route('/', methods=['GET', 'POST'])
def upload_file():                                                              # handles the main page
    if request.method == 'POST':
                                                                                # check if the post request has the file part
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['file']
                                                                                # If the user does not select a file, the browser 
                                                                                # returns to the main page
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        if file and allowed_file(file.filename):                                # if the file is good
            filename = secure_filename(file.filename)                           # get a secure path
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))      # save it 
            filename = filename[0:-4]                                           # get a filename without an extension
            return redirect("/get-report/" + filename)                          # transition   
                                                                                # HTML for the main page: besides requesting a report,
                                                                                # allows to generate a link where result is stored#
                                                                                
    return '''
    <!doctype html>
    <title>Upload new Files</title>
    <h1>Upload new File</h1>
    <form method=post enctype=multipart/form-data>
      <input type=file name=file id="file" onchange="getFileData(this);">
      <input type=submit value=Upload>
    </form>
    <button type="button" id="copy_link" value = "link"  onclick="myFunction();">Generate a link</button>
    <div id="link"></div>
    <script>
        var filename = ""; 
        let hostname = window.location.origin;
        function getFileData(myFile){
           var file = myFile.files[0];  
           filename = file.name;
        }
        
        function myFunction() {
                if (filename != ""){
                        document.getElementById("link").innerHTML = hostname+"/get-report/"+filename.slice(0, -4);       
                    }else{
                        document.getElementById("link").innerHTML = "Pick a file to upload first"
                    }

          }
    </script>
    '''




@app.route("/get-report/<filename>")
def get_data(filename):                                                     
    filename = filename + ".txt"
                                                                                # call to generate a report
    r = command_line_client.prepare_report(os.path.join(app.config['UPLOAD_FOLDER'], filename)) 
    filename = filename[0:-4]
    if r :
        return render_template(filename+"_out_Table.html")                      # if everything was successful get the table
    else:
        return render_template("out_of_req.html")                               # if we ran out of requests show the explanation page


if __name__ == '__main__':
  app.run(host="0.0.0.0", debug=True)                                           # starts the Flask app
  #app.run( debug=True)                                                         # use this one to run in python IDE