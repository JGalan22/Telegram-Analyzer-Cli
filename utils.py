import re
import configparser
import json
import vt
import typer

from telethon import types, utils
from models import Channel, Message, Url
from datetime import date, datetime
from telethon.tl import patched
from maltiverse import Maltiverse
from diario import Diario

EXTENSIONS_DOC = [".pdf",".doc", ".xls", ".ppt"]


def ReadConfig():
    # Reading Configs
    config = configparser.ConfigParser()
    config.read("config.ini")

    # Setting configuration values
    api_id = config["Telegram"]["api_id"]
    api_hash = config["Telegram"]["api_hash"]
    api_hash = str(api_hash)
    phone = config["Telegram"]["phone"]
    username = config["Telegram"]["username"]
    maltiverse_token = config["APIs"]["maltiverse_token"]
    diario_secret = config["APIs"]["diario_secret"]
    diario_token = config["APIs"]["diario_token"]
    vt_token = config["APIs"]["virustotal_token"]
    return api_id, api_hash, phone, username, maltiverse_token, diario_secret, diario_token, vt_token

def FindUrl(string): 
    regex = r"(?i)\b((?:https?://|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:'\".,<>?«»“”‘’]))"
    url = re.findall(regex,string)       
    return [x[0] for x in url] 

def IsValidExtension(extension_file):
    for ext in EXTENSIONS_DOC:
        if ext in extension_file:
            return True
    return False

def AnalyseUrls(urls: []):
    api = Maltiverse()
    for url in urls:
        typer.echo(f"Sending {url.url} to Maltiverse")
        result = api.url_get(url.url)
        if "blacklist" in result:
            url.urlchecksum = result["urlchecksum"]
            url.classification = result["classification"]
            url.malicious = True
            url.detected_by = "Maltiverse"
            for item in result["blacklist"]:
                description = item["description"]
                source = item["source"]
                url.info_malicious.append(f"{description}(by {source})")

    return urls


def AnalyseDiarioDocuments(file_name: str, message: Message,diario_token, diario_secret):
    api = Diario(diario_token, diario_secret)
    request_upload = api.upload(file_name)
    if request_upload.data:
        message.hash = request_upload.data["hash"]
        typer.echo(f"The hash asociated to the file {file_name} is {message.hash}") 
        response = api.search(message.hash)
        if response.data:
            status = response.data["status"]
            typer.echo(f"Status from file {file_name} in Diario is {status}")
            message.sha1 = response.data["sha1"]
            message.sha256 = response.data["sha256"]
            message.md5 = response.data["md5"]
            message.type = response.data["documentType"]
            message.prediction = response.data["prediction"]
            message.detected_by = "Diario"
        else:
            typer.echo(f"There are an error searching the file {request_upload.error}") 
    else:
        typer.echo(f"There are an error uploading the file {request_upload.error}")      

async def AnalyseVirusTotalDocuments(file_name: str, message: Message,vt_token):
    try:
        api = vt.Client(vt_token)
        with open(file_name, "rb") as f:
            typer.echo(f"Uploading file {file_name}")
            analysis = await api.scan_file_async(f, wait_for_completion=True)
        typer.echo(f"Analysis ID: {analysis.id}")

        # Retrieve basic info about file analised
        basic_info =  await api.get_async("/analyses/{}",analysis.id)
        basic_json = await basic_info.json_async()
        data_info = basic_json["data"]
        stats = data_info["attributes"]["stats"]
        message.prediction = IsMalware(stats)

        meta_json = await basic_info.json_async()
        meta_info = (meta_json["meta"])["file_info"]
        message.sha1 =  meta_info["sha1"]
        message.sha256 = meta_info["sha256"]
        message.hash = message.sha256
        message.md5 = meta_info["md5"]
        message.detected_by = "Virustotal"

        # Retrieve more info about file
        typer.echo(f"Sha256 is {message.sha256}")
        advanced_info = await api.get_async("/files/{}", message.sha256)
        advanced_json = await advanced_info.json_async()
        message.type = advanced_json["data"]["attributes"]["magic"]
    except:
        typer.echo("Error retrieving report from Virustotal")
    finally:
        await api.close_async()

def IsMalware(stats):
    malicious = stats["malicious"]
    suspicious = stats["suspicious"]
    return "Malicious" if (malicious > 0 or suspicious > 0) else "Harmless"

def MapperDialogToChannel(dialog: object, current_user_id: str):
    try:
        type(dialog)
        title = utils.get_display_name(dialog.entity)
        is_channel = type(dialog.entity) == types.Channel
        id_channel = dialog.entity.id
        verified = dialog.entity.verified if is_channel else None
        megagroup = dialog.entity.megagroup if is_channel else None
        participants_count = dialog.entity.participants_count
        access_hash = dialog.entity.access_hash if is_channel else None
        username = dialog.entity.username if is_channel else None
        date = dialog.entity.date
        channel = Channel(title,is_channel,id_channel,verified,megagroup,participants_count,access_hash,username,date, current_user_id)
        return channel
    except Exception as ex:
        print(ex)
    

async def MapperConversationToMessage(message: object):
    id_msg = message.id
    id_from = message.from_id
    date = message.date
    msg = message.message
    if message.media and type(message.media) != types.MessageMediaWebPage:
        id_media = message.media.document.id
        file_name = GetFilename(message.media.document.attributes)
        access_hash_media = message.media.document.access_hash
        size_media = message.media.document.size
    else:
        id_media = None
        file_name = None
        access_hash_media = None
        size_media = None
    msg = Message(id_msg,id_from,date,msg,id_media,file_name,access_hash_media,size_media)
    return msg

def GetFilename(attributes: [object]):
    response = None
    for attr in attributes:
        if type(attr) == types.DocumentAttributeFilename:
            response = attr.file_name
    
    return response

def MapperListToUrlsObject(urls_to_add: []):
    urls = []
    for item in urls_to_add:
        urls.append(Url(item))
    return urls

def extractJsonString(msgs: []):
    response = []
    for msg in msgs:
        response.append(json.dumps(msg.__dict__, default=CustomJsonParser))
    return response


def CustomJsonParser(o):
    if isinstance(o, datetime):
        return o.__str__()

def ReadRestrictedWordList(file_name:str):
    with open(file_name) as reader:
        line =reader.readline()
    return line