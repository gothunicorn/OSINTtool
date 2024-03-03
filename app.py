# from flask import Flask, request, render_template

# app = Flask(__name__)

# @app.route('/')
# def index():
#     return render_template('login.html')

# @app.route('/index')
# def index1():
#     return render_template('index.html')

from flask import Flask, request, render_template, redirect, url_for
from flask_socketio import SocketIO, send
import requests
from flask_cors import CORS
import mysql.connector
import socket
import ssl
import threading

app = Flask(__name__)
CORS(app)
app.config['SECRET'] = "secret!123"
socketio = SocketIO(app, cors_allowed_origins="*")

# MySQL configuration
mysql_config = {
    'host': 'localhost',
    'user': 'root',
    'password': 'namita21',
    'database': 'cid_db'  # your database name
}

# Function to validate user credentials
def authenticate_user(username, password):
    conn = mysql.connector.connect(**mysql_config)
    cursor = conn.cursor()

    # Query the database for the user with the provided username and password
    query = "SELECT * FROM user WHERE username = %s AND pword = %s"
    cursor.execute(query, (username, password))
    user = cursor.fetchone()

    cursor.close()
    conn.close()

    return user

def check_ssl_tls_configuration(website_url):
    """
    Check SSL/TLS configuration for a given website.
    """
    try:
        # Create a socket
        sock = socket.create_connection((website_url, 443))

        # Wrap the socket with SSL
        ssl_sock = ssl.wrap_socket(sock, ssl_version=ssl.PROTOCOL_SSLv23)

        # Get the SSL/TLS configuration information
        cipher = ssl_sock.cipher()
        return {
            "website_url": website_url,
            "protocol_version": ssl_sock.version(),
            "cipher_suite": cipher[0],
            "message": "SSL/TLS Configuration is secure."
        }
        
    except ssl.SSLError as e:
        return {
            "website_url": website_url,
            "message": f"Error: {e}"
        }
    except Exception as e:
        return {
            "website_url": website_url,
            "message": f"Error: {e}"
        }
    finally:
        # Close the SSL socket
        ssl_sock.close()
        sock.close()

def scan_ports(website, port_range):
    open_ports = []
    try:
        if not website.replace(".", "").isdigit():
            ip = socket.gethostbyname(website)
        else:
            ip = website

        def scan_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    open_ports.append(port)
                sock.close()
            except:
                pass

        threads = []
        for port in range(port_range[0], port_range[1] + 1):
            t = threading.Thread(target=scan_port, args=(port,))
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        if open_ports:
            return f"Open ports on website {website}: {open_ports}"
        else:
            return f"No open ports found on website {website}."
    except socket.gaierror:
        return f"Failed to resolve website {website}."
    except Exception as e:
        return f"Failed to scan ports on website {website}: {e}"


@app.route('/')
def loginenter():
    return render_template('login.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Check if the provided username and password match any records in the database
        user = authenticate_user(username, password)

        if user:
            # Authentication successful, redirect to the home page
            return redirect(url_for('index1'))
        else:
            # Authentication failed, display an error message
            return render_template('login.html', error='Invalid username or password')

    # If the request method is GET, render the login page
    return render_template('/login.html')

@app.route('/scan', methods=['POST'])
def scan():
    website_url = request.form['website_url']
    ssl_tls_result = check_ssl_tls_configuration(website_url)
    port_scan_result = scan_ports(website_url, (1, 1000))  # Adjust port range as needed
    return render_template('results.html', website=website_url, ssl_tls_result=ssl_tls_result, port_scan_result=port_scan_result)

@app.route('/index')
def index1():
    return render_template('index.html')

# @app.route('/about')
# def about():
#     return render_template('about.html')

@app.route('/services')
def services():
    return render_template('services.html')

@socketio.on('message')
def handle_message(message):
    print("Received message: " + message)
    if message != "User connected!":
        send(message, broadcast=True)

@app.route('/portfolio')
def portfolio():
    return render_template('portfolio.html')

@app.route('/team')
def team():
    return render_template('team.html')

@app.route('/blog')
def blog():
    return render_template('blog.html')

@app.route('/contact')
def contact():
    return render_template('contact.html')

@app.route('/upload', methods=['POST'])
def upload():
    if 'fileInput' in request.files:
        file = request.files['fileInput']
        file.save('uploaded_files/' + file.filename)  # Save the uploaded file
        api = "e3ada25d1527cbe7d465c50a9c6241d1ce8e9efdb1928c9f26177f05f15ec4f3"
        url_upload = "https://www.virustotal.com/api/v3/files"
        files = { "file": (str(file.filename), open(str(file.filename), "rb"), "application/pdf") }
        headers_upload = {
            "accept": "application/json",
            "x-apikey": api
        }
        response_upload = requests.post(url_upload, files=files, headers=headers_upload)
        if response_upload.status_code == 200:
            # Parse the JSON response
            response_json = response_upload.json()
            
            # Extract the "id" from the response
            analysis_id = response_json["data"]["id"]
        url1 = "https://www.virustotal.com/api/v3/analyses/"
        url_analysis = url1 + analysis_id

        headers_analysis = {
            "accept": "application/json",
            "x-apikey": api
        }

        response_analysis = requests.get(url_analysis, headers=headers_analysis)
        if response_analysis.status_code == 200:
            # Parse the JSON response
            analysis_json = response_analysis.json()
            
            # Extract the "id" from the response
            sha256 = analysis_json["meta"]["file_info"]["sha256"]
            sha1 = analysis_json["meta"]["file_info"]["sha1"]
            md5 = analysis_json["meta"]["file_info"]["md5"]
        url2 = "https://www.virustotal.com/api/v3/files/"
        url_sha256 = url2 + sha256
        url_sha1 = url2 + sha1
        url_md5 = url2 + md5

        headers_report = {
            "accept": "application/json",
            "x-apikey": api
        }

        response_md5 = requests.get(url_md5, headers=headers_report)

        # Check if the request was successful (status code 200)
        if response_md5.status_code == 200:
            # Parse the JSON response
            md5_report = response_md5.json()
            
            # Extract the last analysis stats
            last_analysis_stats = md5_report["data"]["attributes"]["last_analysis_stats"]

        undetected_value1 = last_analysis_stats['undetected']
        malicious_value1 = last_analysis_stats['malicious']
        suspicious_value1 = last_analysis_stats['suspicious']
        harmless_value1 = last_analysis_stats['harmless']
        timeout_value1 = last_analysis_stats['timeout']
        confirmed_timeout_value1 = last_analysis_stats['confirmed-timeout']
        failure_value1 = last_analysis_stats['failure']
        type_unsupported_value1 = last_analysis_stats['type-unsupported']

        response_sha256 = requests.get(url_sha256, headers=headers_report)

        # Check if the request was successful (status code 200)
        if response_sha256.status_code == 200:
            # Parse the JSON response
            sha256_report = response_sha256.json()
            
            # Extract the last analysis stats
            last_analysis_stats = sha256_report["data"]["attributes"]["last_analysis_stats"]
        undetected_value2 = last_analysis_stats['undetected']
        malicious_value2 = last_analysis_stats['malicious']
        suspicious_value2 = last_analysis_stats['suspicious']
        harmless_value2 = last_analysis_stats['harmless']
        timeout_value2= last_analysis_stats['timeout']
        confirmed_timeout_value2 = last_analysis_stats['confirmed-timeout']
        failure_value2 = last_analysis_stats['failure']
        type_unsupported_value2 = last_analysis_stats['type-unsupported']

        response_sha1 = requests.get(url_sha1, headers=headers_report)

        # Check if the request was successful (status code 200)
        if response_sha1.status_code == 200:
            # Parse the JSON response
            sha1_report = response_sha1.json()
            
            # Extract the last analysis stats
            last_analysis_stats = sha1_report["data"]["attributes"]["last_analysis_stats"]
        undetected_value3 = last_analysis_stats['undetected']
        malicious_value3 = last_analysis_stats['malicious']
        suspicious_value3 = last_analysis_stats['suspicious']
        harmless_value3 = last_analysis_stats['harmless']
        timeout_value3= last_analysis_stats['timeout']
        confirmed_timeout_value3 = last_analysis_stats['confirmed-timeout']
        failure_value3 = last_analysis_stats['failure']
        type_unsupported_value3 = last_analysis_stats['type-unsupported']
        
        # Pass these variables to the template
        return render_template('services_info.html', 
                               undetected1=undetected_value1, malicious1=malicious_value1, 
                               suspicious1=suspicious_value1, harmless1=harmless_value1, 
                               timeout1=timeout_value1, confirmed_timeout1=confirmed_timeout_value1, 
                               failure1=failure_value1, type_unsupported1=type_unsupported_value1,
                               undetected2=undetected_value2, malicious2=malicious_value2, 
                               suspicious2=suspicious_value2, harmless2=harmless_value2, 
                               timeout2=timeout_value2, confirmed_timeout2=confirmed_timeout_value2, 
                               failure2=failure_value2, type_unsupported2=type_unsupported_value2,
                               undetected3=undetected_value3, malicious3=malicious_value3, 
                               suspicious3=suspicious_value3, harmless3=harmless_value3, 
                               timeout3=timeout_value3, confirmed_timeout3=confirmed_timeout_value3, 
                               failure3=failure_value3, type_unsupported3=type_unsupported_value3)
        #return str(file.filename)
    return 'No file uploaded'

if __name__ == "__main__":
    # app.run(debug=True)
    socketio.run(app, host="127.0.0.1", debug=True)
