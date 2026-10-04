import smtplib
from email.mime.text import MIMEText

EMAIL = "your_email@gmail.com"
PASSWORD = "your_app_password"

def send_alert(ip, attack):
    msg = MIMEText(f"🚨 ALERT!\n\nIP: {ip}\nAttack: {attack}")
    msg["Subject"] = "IDS Alert"
    msg["From"] = EMAIL
    msg["To"] = EMAIL

    try:
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(EMAIL, PASSWORD)
        server.send_message(msg)
        server.quit()

        print("📧 Email alert sent")

    except Exception as e:
        print("❌ Email failed:", e)