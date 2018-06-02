from flask import Flask, render_template, request, redirect, send_from_directory, url_for
from werkzeug import secure_filename
import os
from debugger import *


app = Flask(__name__)

UPLOAD_FOLDER = 'C:\\Users\\dora\\Desktop\\github\\debugger\\GUI\\venv\\web\\static\\uploads\\'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

@app.route('/')
def index():
    return render_template('layout.html')

@app.route('/uploader', methods=['POST'])
def upload_file(filename=None):
    if request.method == 'POST':
        file = request.files['file']
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename)) # uploaded success
        # debug = debugger(filename)
        # debug.create_process(filename)
        # return redirect(url_for('uploaded_file', filename=filename))
    return render_template('layout.html', filename = filename)

# @app.route('/upload')
# def uploaded_file(filename=None):
#     return send_from_directory(app.config['UPLOAD_FOLDER'],
#                                filename)  

@app.route('/hexdump')
def hexdump(filename=None):  
    start_offset=0
    offset = 0
    f = open(filename, 'rb')
    buffer = f.read()

    while offset < len(buffer):
        # Offset
        output += (' %08X : ' % (offset + start_offset))
 
        if ((len(buffer) - offset) < 0x10) is True:
            data = buffer[offset:]
        else:
            data = buffer[offset:offset + 0x10]
 
        # Hex Dump
        for hex_dump in data:
            output += ("%02X" % hex_dump)
 
        if ((len(buffer) - offset) < 0x10) is True:
            output += (' ' * (3 * (0x10 - len(data))))
 
        output += ('  ')
 
        # Ascii
        for ascii_dump in data:
            if ((ascii_dump >= 0x20) is True) and ((ascii_dump <= 0x7E) is True):
                output += (chr(ascii_dump))
            else:
                output += ('.')
 
        offset = offset + len(data)
        output += ''
    return render_template('layout.html', result = output)


# @app.route("/layout", methods=['GET', 'POST'])
# def upload():
# 	if request.method == 'POST':
# 		f = request.files['layout']
# 		filename = secure_filename(f.filename)
# 		f.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
# 		return redirect(url_for('uploaded_file', filename=filename))
# 	return "success"

# @app.route('/layout/<filename>')
# def uploaded_file(filename):
#     return send_from_directory(app.config['UPLOAD_FOLDER'],
#                                filename)

if __name__ == '__main__':
    app.run(debug=True)
