import smtplib
import email.utils
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import envs


def validate_username(username):
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


def sendemail(RECIPIENT, code):
    SENDER = "verification@paris-sanskrit.com"
    SENDERNAME = 'Sanskrit'
    USERNAME_SMTP = envs.USERNAME_SMTP
    PASSWORD_SMTP = envs.PASSWORD_SMTP
    HOST = envs.SMTP_HOST
    PORT = 587

    SUBJECT = "Verify Your Email Address"
    BODY_TEXT = f"Verification Code: {code}"
    BODY_HTML = f"""
    <html>
        <head></head>
        <body style="text-align: center;">
            <br>
            <h2>Verification Code</h2>
            <h4>{code}</h4>
            <br>
            <p>This email was sent by
                <a href='https://paris-sanskrit.com'>Sanskrit</a>
            </p>
            <p>Note, this e-mail was sent from an address that cannot accept incoming e-mails.</p>
        </body>
    </html>
                """

    msg = MIMEMultipart('alternative')
    msg['Subject'] = SUBJECT
    msg['From'] = email.utils.formataddr((SENDERNAME, SENDER))
    msg['To'] = RECIPIENT

    part1 = MIMEText(BODY_TEXT, 'plain')
    part2 = MIMEText(BODY_HTML, 'html')
    msg.attach(part1)
    msg.attach(part2)

    try:  
        server = smtplib.SMTP(HOST, PORT)
        server.ehlo()
        server.starttls()
        server.ehlo()
        server.login(USERNAME_SMTP, PASSWORD_SMTP)
        server.sendmail(SENDER, RECIPIENT, msg.as_string())
        server.close()
    except:
        return False
    else:
        return True