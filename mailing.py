#!/usr/bin/python3.8
import threading
import smtplib
from email.message import EmailMessage
import getpass

def send_email(username, password):
    rcvs = [
        'ismailbensidikhir@gmail.com',
        'ben55066@gmail.com'
    ]

    server = smtplib.SMTP('smtp.gmail.com', 587)
    server.ehlo()
    server.starttls()

    for reciver in rcvs:
        client = [
            'ismail ben sidi khir',
            'ismailox ben'
        ]

        i = 0
        message_ = message(client[i])
        msg = EmailMessage()
        msg['Subject'] = 'Testing Email by Using Python3.8'
        msg['From'] = f'{username}@gmail.com'
        msg['To'] = reciver
        msg.set_content(message_)
        server.login('{}@gmail.com'.format(username), password)
        server.send_message(msg)
        i += 1

def message(client):
    return f'''
    Hello {client}
    Welcome to My testing email by using python language
    this script Will contains multiple par
    first part contains the Subject
    second part contains the Destination email
    third part contains the sender email 
    and in the Last part we will explain what we want
    to send to the destination EMAIL
    Thank You!
    '''

def get_username():
    username = input("    Username: ")
    return username

def get_password():
    password = getpass.getpass("    Password: ")
    return password

def main():
    print('{}{}{}'.format('-' * 18, ' Log-in ', '-' * 18))
    username = get_username()
    password = get_password()
    thread = threading.Thread(target=send_email, args=[username.strip(), password.strip()])
    thread.start()

if __name__ == '__main__':
    main()


