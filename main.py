import requests
import cylance_detection as cylance
import logging
import click
import urllib.parse
import os
import ConfigParser

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(name)-15s [%(levelname)-8s]: %(message)s',
                        datefmt='%m/%d/%Y %I:%M:%S %p')
logger = logging.getLogger(__name__)

Config = ConfigParser.ConfigParser()
Config.read(os.path.join(os.path.abspath(os.path.dirname(__file__)), 'Cylance_creds'))

# Create your own slackbot
hubot_webhook_url = Config.get('Settings', 'Slackbot_Url')


# Send slack alert via hubot for each high or critical detection in cylance
def send_hubot_alert_cylance(threat):
    logger.info("Send hubot alert for detection %s" % threat.name)

    # Emoji for slack based on action taken
    green_alerts = ['Quarantined', 'Whitelisted', 'Default']
    amber_alerts = ['Corrupt', 'FileRemoved']
    red_alerts = ['Suspicious']

    alerts = []
    if threat.action:
        if list(set(threat.action).intersection(red_alerts)):
            alerts.append(':red-alert: Allowed')
        if list(set(threat.action).intersection(green_alerts)):
            alerts.append(':green-alert: Blocked')
        if list(set(threat.action).intersection(amber_alerts)):
            alerts.append(':amber-alert: Damaged')

    if threat.score < -0.5:
        threat.severity = 'High'
    elif threat.score > -0.5 and threat.score < 0:
        threat.severity = 'Medium'
    else:
        threat.severity = 'Unknown'

    message_to_send = ":cylance: *%s* Alert: <%s|%s> ---> %s\n" % (
    threat.severity, threat.link, threat.name, str(alerts).strip('[').strip(']').replace("'", ""))
    message_to_send = "%sDevices: %s\n" % (message_to_send, str(threat.devices).strip('[').strip(']').replace("'", ""))
    message_to_send = "%sHash: %s\n" % (message_to_send, threat.hash)
    message_to_send = "%sPath: %s\n" % (
    message_to_send, str(threat.path).strip('[').strip(']').replace("'", "").replace('\\\\', '\\'))
    if threat.action:
        message_to_send = "%sAction Taken: %s" % (
        message_to_send, str(threat.action).strip('[').strip(']').replace("'", ""))
    else:
        message_to_send = "%sAction Taken: %s" % (message_to_send, 'None')

    # Whom to send the alert
    send_to = 'Your channel or username'
    data = {'message': message_to_send, 'users': send_to}
    data = urllib.parse.urlencode(data)

    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    resp = requests.post(hubot_webhook_url, headers=headers, data=data)
    if resp.ok:
        logger.info("Sent alert to user/channel %s" % send_to)
        return True
    else:
        logger.critical("Unable to connect to hubot.")
        logger.info("Hubot Error %d:%s" % (resp.status_code, resp.text))
        return False


@click.command()
@click.option("-d", "--duration", default=600, show_default=True, nargs=1, type=int, required=False, help="Cylance detections that were last seen since 'duration' seconds")
def main(duration):
    cylance_threats = cylance.fetch_detections(duration)
    if cylance_threats:
        logger.info("Sending alerts")
        for threat in cylance_threats:
            send_hubot_alert_cylance(threat)


if __name__ == '__main__':
    main()
