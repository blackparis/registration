import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import envs


def validate_username(username):
    if len(username) > 18:
        return 0
    if not username[0].isalnum() or not username[-1].isalnum():
        return 0
    for c in username:
        if not c.isalnum():
            if c != '.' and c != '_' and c != '-':
                return 0
    return 1


def validate_password(password):
    for c in password:
        if c == " ":
            return 0
    if len(password) < 6:
        return 0
    if password.isalpha():
        return 0
    if password.isnumeric():
        return 0
    return 1


def validate_email(email):
    pos_AT = 0
    count_AT = 0
    count_DT = 0
    if email[0] == '@' or email[-1] == '@':
        return 0
    if email[0] == '.' or email[-1] == '.':
        return 0
    for c in range(len(email)):
        if email[c] == '@':
            pos_AT = c
            count_AT = count_AT + 1
    if count_AT != 1:
        return 0
        
    username = email[0:pos_AT]
    if not username[0].isalnum() or not username[-1].isalnum():
        return 0
    for d in range(len(email)):
        if email[d] == '.':
            if d == (pos_AT+1):
                return 0
            if d > pos_AT:
                word = email[(pos_AT+1):d]
                #print(word)
                if not word.isalnum():
                    return 0
                pos_AT = d
                count_DT = count_DT + 1
    if count_DT < 1 or count_DT > 2:
        return 0
        
    return 1


def sendemail(email, code):
    BODY_HTML = f"""
    <html>
        <head></head>
        <body style="text-align: center;">
            <br>
            <h2>Verification Code</h2>
            <h4>{code}</h4>
            <br>
            <p>This email was sent by
                <a href='https://paris-sanskrit.herokuapp.com'>Sanskrit</a>
            </p>
            <p>Note, this e-mail was sent from an address that cannot accept incoming e-mails.</p>
        </body>
    </html>
                """
    msg = MIMEMultipart("alternative")
    msg["From"] = envs.ADMIN_EMAIL_ADDRESS
    msg["To"] = email
    msg["Subject"] = "verify our email address"
    msg.attach(MIMEText(BODY_HTML, 'html'))
    try:
        server = smtplib.SMTP("smtp-mail.outlook.com", 587)
        server.starttls()
        server.login(envs.ADMIN_EMAIL_ADDRESS, envs.ADMIN_EMAIL_PASSWORD)
        server.sendmail(envs.ADMIN_EMAIL_ADDRESS, email, msg.as_string())
        server.quit()
    except:
        return False
    else:
        return True