import requests
import urllib3
import threading
import sys
import time
import json


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def Get_Website(instance, protocol, port):

    splunk = Splunk()
    ip = instance['dynamicData']['publicIpAddress']

    try:
        git_head = requests.get('{}://{}:{}/.git/HEAD'.format(protocol, ip, port), verify=False, timeout=3)
        if git_head.status_code == 200 or git_head.status_code == 403:
            if 'ref: refs/head' in git_head.text:
                git_head = git_head.text
                print('-- {}://{}:{}/.git/HEAD exists! Discovered via ref in HEAD file - High confidence this is actually exposed'.format(protocol, ip, port))
                print('-- HEAD info: {}'.format(git_head))
                print('---')
                print('-- Making additional requests for more details.')
                try:
                    git_history = requests.get('{}://{}:{}/.git/logs/HEAD'.format(protocol, ip, port), verify=False, timeout=3)
                    git_history = git_history.text
                    print('-- Additional git repo details: {}'.format(git_history))
                    print('---')
                except Exception:
                    git_history = 'Could not pull git history data'
                    print('---')
                    pass
                try:
                    git_config = requests.get('{}://{}:{}/.git/config'.format(protocol, ip, port), verify=False, timeout=3)
                    git_config = git_config.text
                    print('-- Git Config File: {}'.format(git_config))
                    print('---')
                except Exception:
                    git_config = 'Could not pull config data'
                    print('---')
                    pass

                # Since we're inside a thread, just call the send to splunk function within the thread, send the data and move on.
                # We're not expecting very many of these, so pushing each finding one at a time to splunk isn't a big deal.
                # if the expectation was to have several we could shove this data into a list and then bulk upload with one large payload.

                splunk.Build_Splunk_Payload(instance, protocol, ip, port, git_head, git_history, git_config)

    except Exception:
        pass


class Splunk:
    def __init__(self):
        self.splunk_token = ''
        self.splunk_url = ''

    def __Send_To_Splunk(self, payload):
        print('Sending this to splunk:')
        print(payload)

        header = {'Authorization': 'Splunk {}'.format(self.splunk_token)}
        response = requests.post(self.splunk_url, headers=header, data=payload)

        if response.status_code != 200 or not requests:
            raise ValueError('Unable to connect to Splunk: {} - {} status code recieved'.format(response.status_code, response.reason))
        else:
            print('Splunk Connection Successful')

    def Build_Splunk_Payload(self, instance, protocol, ip, port, git_head, git_history, git_config):
        print('-- Building data to go to splunk:')
        # Lets add some enrichment details to this data.
        note = '{}://{}:{}/.git/HEAD'.format(protocol, ip, port)

        instance.update({
            'enrichment_request_url': note,
            'enrichment_request_protocol': protocol,
            'enrichment_request_port': port,
            'enrichment_git_head': git_head,
            'enrichment_git_history': git_history,
            'enrichment_git_config': git_config,
            'alert_name': 'exposed_git_directory'
            })

        dumped_instance_data = json.dumps(instance)
        print('-- Dumped Instance Data: ' + dumped_instance_data + '\n\n')
        print('-- Building Payload')

        index = ''
        sourcetype = 'git-checker'
        payload = {'index': index, 'sourcetype': sourcetype, 'event': dumped_instance_data, 'time': time.time()}
        formated_payload = json.dumps(payload)
        self.__Send_To_Splunk(formated_payload)


class Prisma:
    def __init__(self):
        self.base_url = 'https://api.prismacloud.io'
        self.prisma_username = ''
        self.prisma_password = ''
        self.prisma_customer = ''

    def Lets_Login(self):
        headers = {'accept': "application/json; charset=UTF-8", 'content-type': "application/json; charset=UTF-8"}
        login_payload = '{"username":"{}","password":"{}","customerName":"{}"}'.format(self.prisma_username, self.prisma_password, self.prisma_customer)
        login_url = self.base_url + '/login'

        login_response = requests.request("POST", url=login_url, data=login_payload, headers=headers)

        if login_response.json()['message'] == 'login_successful':
            jwt = login_response.json()['token']
            return jwt
        else:
            print('--- Login Failed: {}'.format(str(login_response)))
            sys.exit()

    def Pull_Data(self, jwt, port):
        headers = {'accept': "application/json; charset=UTF-8", 'content-type': "application/json; charset=UTF-8", 'x-redlock-auth': jwt}
        request_url = self.base_url + '/search/config'

        payload = """{"query":"config where api.name = 'aws-ec2-describe-instances' as X; config where api.name = 'aws-ec2-describe-security-groups' as Y; filter '$.Y.ipPermissions[*].toPort is member of (""" + port + """) and $.X.state.name == running'; show X; addcolumn state.name instanceId privateIpAddress publicIpAddress", "timeRange":{"type":"relative","value":{"unit":"hour","amount":24}}}"""

        try:
            query_response = requests.request("POST", url=request_url, data=payload, headers=headers)
            return query_response

        except Exception:
            print('--- Something went wrong while checking port {}. Here is the response: {}'.format(port, str(query_response)))
            print('--- Everyone wants some magical solution for their problem and everyone refuses to believe in magic. - Hatter')
            pass

    def Process_The_Data(self, query_response, port, protocol):
        for instance in query_response.json()['data']['items']:
            if instance['dynamicData']['state.name'] == 'running':
                if 'publicIpAddress' in instance['dynamicData']:
                    x = threading.Thread(target=Get_Website, args=(instance, protocol, port,))
                    x.start()


def Main():
    # Common web ports and protocols, add more as necsssary
    port_protocol = {
        '80': 'http',
        '443': 'https',
        '3000': 'http',
        '8000': 'http',
        '8080': 'http'
        }

    prisma = Prisma()

    # Authenticating to prisma, getting authentication jwt.
    jwt = prisma.Lets_Login()

    for port, protocol in port_protocol.items():
        print('- Checking Port: ' + port)
        print('-- Grabbing the data from Prisma, one moment please...')

        # Grab the data from prisma
        query_response = prisma.Pull_Data(jwt, port)
        print('-- Done grabbing data, starting to process the data...')

        # Query the ip/page to determine if its listening
        prisma.Process_The_Data(query_response, port, protocol)
        print('- Done making requests, threads closing out, moving to next port.')


if __name__ == "__main__":
    Main()
