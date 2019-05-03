import httplib2
import base64
import email
from googleapiclient import errors
from googleapiclient.discovery import build
from django.http import HttpResponseBadRequest
from django.http import HttpResponseRedirect
from .models import CredentialsModel, TrackStatus
from gfglogin import settings
from oauth2client.contrib import xsrfutil
from oauth2client.client import flow_from_clientsecrets
from oauth2client.contrib.django_util.storage import DjangoORMStorage
from django.shortcuts import render
from httplib2 import Http
from django.contrib.auth.decorators import login_required
from django.contrib.auth import login, authenticate
from django.contrib.auth.forms import UserCreationForm
from django.shortcuts import render, redirect
import datetime
from bs4 import BeautifulSoup
import re


def home(request):
    status = True
    if not request.user.is_authenticated:
        return HttpResponseRedirect('admin')

    storage = DjangoORMStorage(CredentialsModel, 'id', request.user, 'credential')
    credential = storage.get()
    try:
        access_token = credential.access_token
        resp, cont = Http().request("https://www.googleapis.com/auth/gmail.readonly",
                                    headers={'Host': 'www.googleapis.com',
                                             'Authorization': access_token})
    except:
        status = False
        print('Not Found')

    #return render(request, 'home.html', {'status': status})
    return renderHome(request)


class Applied:
    def __init__(self,company,title,date):
        self.company=company
        self.title=title
        self.date=date

def renderHome(request):
    status = True
    applied = [Applied("ABC","Software Dev","02/12/2018"),Applied("QWE","Software Dev","02/12/2018"),
               Applied("PLO","Software Dev","02/12/2018")]
    print(request.user)
    applied_data = TrackStatus.objects.filter(userid=request.user.username, status="Applied")
    assesment_data = TrackStatus.objects.filter(userid=request.user.username, status="Assessment")
    offer_data = TrackStatus.objects.filter(userid=request.user.username, status="Offer")
    rejected_data = TrackStatus.objects.filter(userid=request.user.username, status="Rejected")
    return render(request, 'newhome.html', {
        'applied' : applied_data,
        'username' : request.user,
        'applied_count' : len(applied_data),
        'assesment': assesment_data,
        'assesment_count': len(assesment_data),
        'offer':offer_data,
        'offer_count':len(offer_data),
        'rejected':rejected_data,
        'rejected_count':len(rejected_data),
        'status': status})

def signup(request):
    if request.method == 'POST':
        form = UserCreationForm(request.POST)
        if form.is_valid():
            form.save()
            username = form.cleaned_data.get('username')
            raw_password = form.cleaned_data.get('password1')
            user = authenticate(username=username, password=raw_password)
            login(request, user)
            return redirect('home')
    else:
        form = UserCreationForm()
    return render(request, 'signup.html', {'form': form})


FLOW = flow_from_clientsecrets(
    settings.GOOGLE_OAUTH2_CLIENT_SECRETS_JSON,
    scope='https://www.googleapis.com/auth/gmail.readonly',
    redirect_uri='http://cloudproject2.appspot.com/oauth2callback',
    prompt='consent')


def GetMessageBody(service, user_id, msg_id):
    try:
        message = service.users().messages().get(userId=user_id, id=msg_id, format='raw').execute()
        msg_str = base64.urlsafe_b64decode(message['raw'].encode('ASCII'))
        mime_msg = email.message_from_bytes(msg_str)
        messageMainType = mime_msg.get_content_maintype()
        if messageMainType == 'multipart':
            for part in mime_msg.get_payload():
                if part.get_content_maintype() == 'text':
                    return part.get_payload()
            return ""
        elif messageMainType == 'text':
            return mime_msg.get_payload()
    except errors.HttpError as error:
        print ('An error occurred: %s' % error)


def get_emails_for_given_parameters(request):
    topic = "Workday"
    topic2 = "\"You have been invited to attend the challenge\""
    storage = DjangoORMStorage(CredentialsModel, 'id', request.user, 'credential')
    credential = storage.get()
    SCOPES = ['https://www.googleapis.com/auth/calendar']
    if credential is None or credential.invalid:
        FLOW.params['state'] = xsrfutil.generate_token(settings.SECRET_KEY,
                                                       request.user)
        authorize_url = FLOW.step1_get_authorize_url()
        return HttpResponseRedirect(authorize_url)
    else:
        http = httplib2.Http()
        http = credential.authorize(http)
        service = build('gmail', 'v1', http=http)
        print('access_token = ', credential.access_token)
        status = True
        results = service.users().messages().list(userId='me', labelIds=['INBOX'], q=topic2).execute()
        messages = results.get('messages', [])
        print("Length", len(messages))
        if not messages:
            print("No messages found.")
        else:
            print("Message snippets:")
            for message in messages:
                msg = service.users().messages().get(userId='me', id=message['id'], format='full').execute()
                # print(msg['snippet'])
                tmp = GetMimeMessage(msg)
                from_e = get_from(msg)
                print(clean_up_from(from_e), get_email_timestamp(msg))
                company_name = clean_up_from(from_e)
                date = get_email_timestamp(msg)
                #                creds = None
                #                # The file token.pickle stores the user's access and refresh tokens, and is
                #                # created automatically when the authorization flow completes for the first
                #                # time.
                #                if os.path.exists('token.pickle'):
                #                    with open('token.pickle', 'rb') as token:
                #                        creds = pickle.load(token, encoding="latin1")
                #
                #                # If there are no (valid) credentials available, let the user log in.
                #                if not creds or not creds.valid:
                #                    if creds and creds.expired and creds.refresh_token:
                #                        creds.refresh(Request())
                #                    else:
                #                        flow = InstalledAppFlow.from_client_secrets_file(
                #                            'client_secrets.json', SCOPES)
                #                        creds = flow.run_local_server()
                #                    # Save the credentials for the next run
                #                    with open('token.pickle', 'wb') as token:
                #                        pickle.dump(creds, token)
                #
                #                service = build('calendar', 'v3', credentials=creds)
                #
                #                # Call the Calendar API
                #                now = datetime.datetime.utcnow().isoformat() + 'Z'  # 'Z' indicates UTC time
                #
                #                event = {
                #                    'summary': 'Coding Assesment for ' + company_name,
                #                    'location': '',
                #                    'description': 'Coding Assesment for ' + company_name,
                #                    'start': {
                #                        'dateTime': date,
                #                        'timeZone': 'America/Los_Angeles',
                #                    },
                #                    'end': {
                #                        'dateTime': date,
                #                        'timeZone': 'America/Los_Angeles',
                #                    },
                #                }
                obj = TrackStatus.objects.filter(company=company_name)
                obj.update(status="Assessment")


#                obj.save()
#                event = service.events().insert(calendarId='primary', body=event).execute()
# tmp = cleanup(tmp)
# print re.search("attend the challenge (\w+)", tmp).groups()


def cleanup_mail(message):
    body = message.get_payload()
    asd = " ".join((' '.join(body.splitlines())).split())
    p = ""
    for m in asd.split():
        if m.isalnum():
            p = p + m + " "
    return p


def clean_up_from(msg):
    return (' '.join([item for item in msg.split() if '@' not in item and 'Hiring' not in item and 'Team' not in item]))


def get_result(content):
    res = "NONE"
    #    os.environ["GOOGLE_APPLICATION_CREDENTIALS"]="/path/to/file.json"
    rejected_keywords = ["unfortunately", "different candidate", "another candidate", "can\'t move forward",
                         "cannot move forward", "other candidate"]
    offer_keywords = ["congratulations", "excited to be offering", "offer you", "offer of employment"]
    #    client = language.LanguageServiceClient()
    #    content = content.lower()
    #    document = types.Document(
    #        content=content,
    #        type=enums.Document.Type.PLAIN_TEXT)
    #    annotations = client.analyze_sentiment(document=document)
    #    score = annotations.document_sentiment.score
    #    magnitude = annotations.document_sentiment.magnitude
    #
    #    for index, sentence in enumerate(annotations.sentences):
    #        sentence_sentiment = sentence.sentiment.score
    #        print('Sentence {} has a sentiment score of {}'.format(
    #            index, sentence_sentiment))
    #
    #    print('Overall Sentiment: score of {} with magnitude of {}'.format(
    #        score, magnitude))
    #    if score < 0:
    #        return "Rejected"
    #    if score > 0.5:
    #        return "Offer"
    sentences = re.split(r' [\.\?!][\'"\)\]] *', content)
    for sentence in sentences:
        text = sentence
        print(text)
        #        if score < 0.5:
        for keyword in rejected_keywords:
            if (keyword in text):
                res = "Rejected"
        #        if score > 0:
        for keyword in offer_keywords:
            if (keyword in text):
                res = "Offer"
    return res


def GetMimeMessage(message):
    if 'parts' in message['payload']:
        if (message['payload']['parts'][0]['mimeType'] == 'multipart/alternative' or message['payload']['parts'][0][
            'mimeType'] == 'multipart/related') and 'data' in message['payload']['parts'][0]['parts'][0]['body']:
            message_raw = message['payload']['parts'][0]['parts'][0]['body']['data']
        elif 'data' in message['payload']['parts'][0]['body']:
            message_raw = message['payload']['parts'][0]['body']['data']
        else:
            message_raw = ""
    else:
        message_raw = message['payload']['body']['data']
    msg_str = base64.urlsafe_b64decode(message_raw.encode('ASCII'))
    # print(msg_str)
    mime_msg = email.message_from_bytes(msg_str)
    return mime_msg


def get_from(message):
    if 'headers' in message['payload']:
        for i in message['payload']['headers']:
            if i['name'] == 'From':
                return str(i['value'])


def get_email_timestamp(message):
    date = message['internalDate']
    return datetime.datetime.fromtimestamp(float(date) / 1000).strftime('%Y-%m-%d %H:%M:%S')


def get_only_email_body(content):
    content = content.strip()
    #    content = GetMimeMessage(content)
    soup = BeautifulSoup(content)

    for script in soup(["script", "style"]):
        script.extract()

    text = soup.get_text()

    lines = (line.strip() for line in text.splitlines())
    chunks = (phrase.strip() for line in lines for phrase in line.split("  "))
    text = ' '.join(chunk for chunk in chunks if chunk)
    return text


def gmail_authenticate(request):
    messages = []
    storage = DjangoORMStorage(CredentialsModel, 'id', request.user, 'credential')
    credential = storage.get()
    if credential is None or credential.invalid:
        FLOW.params['state'] = xsrfutil.generate_token(settings.SECRET_KEY,
                                                       request.user)
        authorize_url = FLOW.step1_get_authorize_url()
        return HttpResponseRedirect(authorize_url)
    return filter_messages(request, credential)


def filter_messages(request, credential):
    messagebodydict = {}
    http = httplib2.Http()
    http = credential.authorize(http)
    service = build('gmail', 'v1', http=http)
    print('access_token = ', credential.access_token)
    status = True
    filter_applied = ["Thank you for applying", "Thank you for your interest", "Thanks for applying",
                      "Thanks for your interest", "unfortunately", "different candidate", "another candidate",
                      "can\'t move forward", "cannot move forward", "other candidate",
                      "congratulations", "excited to be offering", "offer you", "offer of employment"]
    #    companies = ["Microsoft","Airbnb","Goldmansachs","Twilio"]
    companies = ["Microsoft", "Salesforce", "Airbnb", "Goldmansachs", "Twilio", "Yext"]
    job_roles = ["Software Engineer Intern", "Software Engineer Summer Intern", "Software Engineer - Master's (Intern)",
                 "Platform Software Engineer", "Software Engineer - Intern - Summer", "Software Engineer"]
    count = 0
    for c in companies:

        results = service.users().messages().list(userId='me', labelIds=['INBOX'], q=c).execute()
        messages = results.get('messages', [])
        if not messages:
            print("No messages found.")
        else:

            for message in messages:
                msg = service.users().messages().get(userId='me', id=message['id']).execute()
                date = msg['internalDate']
                date = str(datetime.datetime.fromtimestamp(float(date) / 1000).strftime('%Y-%m-%d %H:%M:%S'))
                msgbody = GetMessageBody(service, 'me', message['id'])
                cleanedmsgbody = get_only_email_body(msgbody)
                position = "Software Engineer"
                if any(x in cleanedmsgbody for x in filter_applied):
                    for job_role in job_roles:
                        if job_role in cleanedmsgbody:
                            position = job_role
                            break
                    count += 1
                    entry = TrackStatus.objects.create(
                        messageid=message['id'],
                        userid=request.user,
                        date=date,
                        company=c,
                        job_role=position,
                        status="Applied"
                    )

                    print(cleanedmsgbody)
                    print("#############################################################################")
                    messagebodydict[c] = msgbody

    print("TOTAL", count)
    get_emails_for_given_parameters(request)
    for c in messagebodydict:
        curr_obj = TrackStatus.objects.filter(company=c)[0]
        curr_status = curr_obj.status
        print(curr_status)
        status_res = get_result(messagebodydict[c])
        if status_res == "NONE":
            status_res = curr_status
        obj = TrackStatus.objects.filter(company=c)
        obj.update(status=status_res)
    return render(request, 'index.html', {'status': status})

def auth_return(request):
    get_state = bytes(request.GET.get('state'), 'utf8')
    if not xsrfutil.validate_token(settings.SECRET_KEY, get_state,
                                   request.user):
        return HttpResponseBadRequest()
    credential = FLOW.step2_exchange(request.GET.get('code'))
    storage = DjangoORMStorage(CredentialsModel, 'id', request.user, 'credential')
    storage.put(credential)
    print("access_token: %s" % credential.access_token)
    return HttpResponseRedirect("/")
