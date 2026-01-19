from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file, make_response
import pymysql
import subprocess
import re
import io
import csv
from xhtml2pdf import pisa
from io import BytesIO
from modules import scanner  
from flask import Response, stream_with_context

app = Flask(__name__)
app.secret_key = 'supersecretkey'


conn = pymysql.connect(host='localhost', user='admin', password='AdminPassword', database='pentest_framework')
cursor = conn.cursor()

EMAIL_REGEX = r'^[\w\.-]+@[\w\.-]+\.\w+$'


@app.route('/')
def index():
    if 'user' in session:
        cursor.execute("SELECT * FROM targets WHERE user_id = %s", (session['user_id'],))
        targets = cursor.fetchall()
        return render_template('dashboard.html', username=session['user'], targets=targets)
    return redirect(url_for('login'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']

        if not re.match(EMAIL_REGEX, email):
            flash('Invalid email format', 'error')
        else:
            cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
            if cursor.fetchone():
                flash('Email already exists', 'error')
            else:
                cursor.execute("INSERT INTO users (name, email, password) VALUES (%s, %s, %s)", (name, email, password))
                conn.commit()
                flash('Signup successful! Please login.', 'success')
                return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        cursor.execute("SELECT * FROM users WHERE email = %s AND password = %s", (email, password))
        user = cursor.fetchone()

        if user:
            session['user'] = user[1]  
            session['user_id'] = user[0]
            return redirect(url_for('index'))
        else:
            flash('Invalid credentials', 'error')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully.', 'info')
    return redirect(url_for('login'))


@app.route('/configure', methods=['GET', 'POST'])
def configure():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        url = request.form['url']
        headers = request.form['headers']
        cookies = request.form['cookies']

        cursor.execute("INSERT INTO targets (user_id, url, headers, cookies) VALUES (%s, %s, %s, %s)",
                       (session['user_id'], url, headers, cookies))
        conn.commit()
        flash('Target configured successfully.', 'success')
        return redirect(url_for('index'))

    return render_template('configure.html')


@app.route('/target/<int:target_id>')
def view_target(target_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

 
    cursor.execute("SELECT id, url, headers, cookies, created_at FROM targets WHERE id = %s AND user_id = %s",
                   (target_id, session['user_id']))
    target = cursor.fetchone()

    if not target:
        flash('Target not found or access denied.', 'error')
        return redirect(url_for('index'))


    cursor.execute("""SELECT vuln_type, payload, affected_url, severity, description, 
                      recommended_fix, detected_at 
                      FROM vulnerabilities WHERE target_id = %s ORDER BY detected_at DESC""", (target_id,))
    findings = cursor.fetchall()

    return render_template('view_target.html', target=target, findings=findings)

@app.route('/scan/<int:target_id>')
def scan_target(target_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    cursor.execute("SELECT url FROM targets WHERE id = %s AND user_id = %s", (target_id, session['user_id']))
    target = cursor.fetchone()
    if not target:
        flash("Target not found or access denied.", "error")
        return redirect(url_for('index'))

    scanner.run_all_scans(target_id, target[0])
    flash("Scan completed.", "success")
    return redirect(url_for('view_target', target_id=target_id))


@app.route('/manual_testing/<int:target_id>')
def manual_testing(target_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    cursor.execute("SELECT url FROM targets WHERE id = %s AND user_id = %s", (target_id, session['user_id']))
    target = cursor.fetchone()

    if not target:
        flash("Target not found or access denied.", "error")
        return redirect(url_for('index'))

    return render_template('manual_testing.html', target=target)


@app.route('/run_tool/<tool>/<int:target_id>')
def run_tool(tool, target_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    cursor.execute("SELECT url FROM targets WHERE id = %s AND user_id = %s", (target_id, session['user_id']))
    target = cursor.fetchone()
    if not target:
        flash("Target not found.", "error")
        return redirect(url_for('index'))

    url = target[0]
    def generate():
        try:
            if tool == "nmap":
                cmd = ["nmap", "-A", url]
            elif tool == "nikto":
                cmd = ["nikto", "-h", url]
            elif tool == "sqlmap":
                cmd = ["sqlmap", "-u", url, "--batch"]
            elif tool == "burpsuite":
                subprocess.Popen(["burpsuite"])
                yield "Burp Suite started. Intercept traffic manually."
                return
            elif tool == "wireshark":
                subprocess.Popen(["wireshark"])
                yield "Wireshark opened. Start capturing traffic manually."
                return
            else:
                yield f"{tool} not implemented yet."
                return

            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
           
           # Stream each line of output
            for line in iter(process.stdout.readline, ''):
                yield line.replace('\n', '<br>')
        except Exception as e:
            yield f"Error: {str(e)}\n"

    return Response(stream_with_context(generate()), mimetype='text/html')
            



@app.route('/export/csv/<int:target_id>')
def export_csv(target_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    cursor.execute("SELECT * FROM targets WHERE id = %s AND user_id = %s", (target_id, session['user_id']))
    target = cursor.fetchone()
    if not target:
        flash("Target not found or access denied.", "error")
        return redirect(url_for('index'))

    cursor.execute("SELECT vuln_type, payload, affected_url, severity, description, recommended_fix, detected_at FROM vulnerabilities WHERE target_id = %s", (target_id,))
    findings = cursor.fetchall()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Vulnerability", "Payload", "Affected URL", "Severity", "Description", "Fix", "Detected At"])
    for row in findings:
        writer.writerow(row)

    response = io.BytesIO()
    response.write(output.getvalue().encode('utf-8'))
    response.seek(0)
    output.close()

    return send_file(response, mimetype='text/csv', as_attachment=True, download_name=f'target_{target_id}_scan_results.csv')

@app.route('/export/pdf/<int:target_id>')
def export_pdf(target_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    cursor.execute("SELECT * FROM targets WHERE id = %s AND user_id = %s", (target_id, session['user_id']))
    target = cursor.fetchone()
    if not target:
        flash("Target not found or access denied.", "error")
        return redirect(url_for('index'))

    cursor.execute("""SELECT vuln_type, payload, affected_url, severity, description, recommended_fix, detected_at 
                      FROM vulnerabilities WHERE target_id = %s""", (target_id,))
    findings = cursor.fetchall()

    rendered = render_template('report_pdf.html', target=target, findings=findings)
    pdf = BytesIO()
    pisa_status = pisa.CreatePDF(rendered, dest=pdf)

    if pisa_status.err:
        return f"Error creating PDF: {pisa_status.err}"

    response = make_response(pdf.getvalue())
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = f'attachment; filename=target_{target_id}_report.pdf'
    return response


@app.route('/remove/<int:target_id>', methods=['POST'])
def remove_target(target_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    cursor.execute("SELECT * FROM targets WHERE id = %s AND user_id = %s", (target_id, session['user_id']))
    target = cursor.fetchone()
    if not target:
        flash("Target not found or access denied.", "error")
        return redirect(url_for('index'))

    
    cursor.execute("INSERT INTO deleted_targets (user_id, url, headers, cookies) VALUES (%s, %s, %s, %s)",
                   (target[1], target[2], target[3], target[4]))
    conn.commit()


    cursor.execute("DELETE FROM targets WHERE id = %s AND user_id = %s", (target_id, session['user_id']))
    conn.commit()

    flash("Target removed and saved in history.", "info")
    return redirect(url_for('index'))

@app.route('/history')
def scan_history():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    cursor.execute("""SELECT t.id, t.url, COUNT(v.id) AS total_vulns, MAX(v.detected_at) 
                      FROM targets t 
                      LEFT JOIN vulnerabilities v ON t.id = v.target_id 
                      WHERE t.user_id = %s 
                      GROUP BY t.id
                      ORDER BY MAX(v.detected_at) DESC""", (session['user_id'],))
    history = cursor.fetchall()
    return render_template('history.html', history=history)




if __name__ == '__main__':
    app.run(debug=True)