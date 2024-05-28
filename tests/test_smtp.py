import smtplib

MAIL_SERVER = 'smtp.zoho.com'
MAIL_PORT = 587
MAIL_USERNAME = 'hola@aztros.com'
MAIL_PASSWORD = '$Aztros2022$'

try:
    server = smtplib.SMTP(MAIL_SERVER, MAIL_PORT)
    server.starttls()
    server.login(MAIL_USERNAME, MAIL_PASSWORD)
    print("Successfully connected to the SMTP server.")
    server.quit()
except Exception as e:
    print(f"Failed to connect to the SMTP server: {e}")
