from flask import Flask, render_template, request, redirect, send_from_directory, url_for
from werkzeug import secure_filename
import os
from debugger import *


app = Flask(__name__)

#UPLOAD_FOLDER = 'C:\\Users\\dora\\Desktop\\github\\debugger\\GUI\\venv\\web\\static\\uploads'
#app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

@app.route('/')
def index():
    return render_template('layout.html')

@app.route('/layout', methods=["POST"])
def start():
    file = request.files['file']
    filename = secure_filename(file.filename)
    debug = debugger(filename)
    #debug.create_process(self.filename)
    return redirect(url_for('hexdump', filename=filename))

@app.route('/layout', methods=["POST"])
def hexdump(filename):
    f = open(filename, 'rb')
    offset = 0
    while True:
        buffer = f.read(16)
        buffer_len = len(buffer)
        if buffer_len == 0:
            break

        output += "%08x : " % offset
        
        for i in range(buffer_len):
            if i==8: 
                output += " "
            output += "%02X" % (ord(buffer[i]))

        if buffer_len < 16:
            for i in range(((16 - buffer_len)*3)+1):
                output += " "    
            output += " "
        
        for i in range(buffer_len):
            if (ord(buffer[i]) >= 0x20 and ord(buffer[i]) <= 0x7E):
                output += buffer[i]
            else:
                output += "."
        offset += 16
    f.close(filename)
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
