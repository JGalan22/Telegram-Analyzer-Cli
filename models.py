from datetime import date, datetime
from sqlalchemy import Column, Integer, String, Boolean , DateTime
from sqlalchemy.dialects.postgresql import JSONB
import db

class Channel(db.Base):
    __tablename__= 'channel'


    id_channel = Column(Integer, primary_key=True)
    title = Column(String, nullable = False)
    is_channel = Column(Boolean)
    verified = Column(Boolean)
    megagroup = Column(Boolean)
    participants_count = Column(Integer)
    access_hash = Column(String)
    username = Column(String)
    date = Column(DateTime)
    updated = Column(DateTime)
    last_message_id = Column(Integer)
    current_user_id = Column(String)
    messages = Column(JSONB)
    urls = Column(JSONB)
    restricted_words = Column(String)


    def __init__(self,
                title:str,
                is_channel: bool,
                id_channel: int,
                verified: bool,
                megagroup: bool,
                participants_count: int,
                access_hash: str,
                username: str,
                date: datetime,
                current_user_id:str):
        self.is_channel = is_channel
        self.title = title
        self.date = date
        self.id_channel = id_channel
        self.participants_count = participants_count
        self.updated = date.now()
        self.last_message_id = 0
        self.urls = []
        self.messages = []
        self.current_user_id = current_user_id
        self.restricted_words = []
        if is_channel:
            self.verified = verified
            self.megagroup = megagroup
            self.access_hash = access_hash
            self.username = username
        else:
            self.verified = None
            self.megagroup = False
            self.access_hash = None
            self.username = None
        

    def __str__(self):
        type = "Public Channel" if self.is_channel else "Chat/Private Channel"
        return f"{type} \t {self.id_channel} \t {self.title} \t Megagroup:{self.megagroup} \t Participants:{self.participants_count}"
    
    def GetRepresentationInList(self):
        type = "Public Channel" if self.is_channel else "Chat/Private Channel"
        return [type,str(self.id_channel), self.title, str(self.megagroup),str(self.participants_count)]

    
class Message():
    
    def __init__(self,
                id_msg: int,
                id_from: int,
                date: datetime,
                message: str,
                id_media: int, # For the message that is a file
                file_name: str,
                access_hash_media:int,
                size_media: int):
        self.id_msg = id_msg
        self.id_from = id_from
        self.date = date
        self.message = message
        self.prediction = None #whether if the media is detected as a malware
        self.detected_by = '' #whether if the media is detected as a malware
        self.type = ''
        self.sha256 = None
        self.sha1 = None
        self.md5 = None
        self.hash = None
        if id_media:
            self.id_media = id_media
            self.file_name = file_name
            self.access_hash_media = access_hash_media
            self.size_media = size_media
        else:
            self.id_media = None
            self.file_name = None
            self.access_hash_media = None
            self.size_media = None


    def __str__(self):
        type = "File" if not self.id_media == '-' else "Message"
        if not self.id_media:
            return f"{type} \t {self.id_msg} \t {self.id_from} \t {self.message} \t {self.date}"
        else:
            return f"{type} \t {self.id_msg} \t {self.id_from} \t {self.message} \t ID Media: {self.id_media} \t File_name: {self.file_name} \t Size:{self.size_media} bytes"

    def GetRepresentationInList(self):
        type = "File" if not self.id_media == '-' else "Message"
        return [type,str(self.id_msg), str(self.id_from), self.message,str(self.id_media),self.file_name,str(self.size_media)]


class Url():

    def __init__(self,url: str):
        self.url = url
        self.malicious = None
        self.detected_by = ''
        self.date = datetime.now()
        self.urlchecksum = None
        self.classification = None
        self.info_malicious = []