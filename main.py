import typer
import db
import asyncio
import json
import os




from telethon import TelegramClient
from telethon import functions, types, utils
from telethon.errors import SessionPasswordNeededError
from models import Channel, Message, Url
from sqlalchemy.exc import IntegrityError, InvalidRequestError, OperationalError
from datetime import date, datetime
from telethon.tl import patched
from maltiverse import Maltiverse
from diario import Diario
from telethon.errors.rpcerrorlist import PhoneNumberInvalidError
from telethon.errors import (
    ChannelInvalidError,
    ChannelPrivateError,
    ChannelsTooMuchError,
    ChannelPublicGroupNaError,
    UserCreatorError,
    UserNotParticipantError,
)
from utils import (
    FindUrl,
    ReadConfig,
    IsValidExtension,
    AnalyseUrls,
    AnalyseDiarioDocuments,
    MapperListToUrlsObject,
    extractJsonString,
    AnalyseVirusTotalDocuments,
    IsMalware,
    MapperDialogToChannel, 
    MapperConversationToMessage,
    ReadRestrictedWordList
    )
  


api_id, api_hash, phone, username, maltiverse_token, diario_secret, diario_token, vt_token = ReadConfig()

app = typer.Typer()


@app.command()
def CheckTelegramConnection():
    """
    Check whether the info to connect to the Telegram API are correct

    """
    # Create the client and connect
    with TelegramClient(username, api_id, api_hash) as client:
        me = client.loop.run_until_complete(authenticate(client))
        me_username= str(me.username)
        typer.echo(
            typer.style(
                "Your username is: " + me_username , fg=typer.colors.BLUE, bold=True
            )
        )


@app.command()
def IsMemberFromChannel(channel):
    """
    Check whether you are a member from the group/channel.

    --channel Channel that you want to check if you are a member or not. Possible value Link(https://t.me/XYXYXY), name(XYXYXY) or ID channel.

    """
    try:
        with TelegramClient(username, api_id, api_hash) as client:
            client.loop.run_until_complete(authenticate(client))

            typer.echo(f"----------------Retrieving Entity from {channel} --------------")

            result = client.loop.run_until_complete(IsMemberOfChannel(client, channel)) is not None

            if result:
                typer.echo(f"Fine! You are a member from {channel}")
            else:
                typer.echo(f"Oops! You are not a member from {channel}")
    
    except ValueError as ex:
        typer.echo(typer.style("The channel is invalid.", fg=typer.colors.RED, bold=True))
        


@app.command()
def SaveBulkChannels(limit: int = None):
    """
    Save/update channels in database that you are a memeber now.\n
    --limit To limit the output, default is None

    """
    with TelegramClient(username, api_id, api_hash) as client:
        client.loop.run_until_complete(authenticate(client))
        typer.echo(f"Retriving data and saving in database.")
        client.loop.run_until_complete(SaveDialogs(client, limit))


@app.command()
def SaveInfoSpecificChannel(channel_id: int):
    """
    Save/update information about specific channel in database with channel id.\n
    --channel_id ID channel to identify it

    """
    with TelegramClient(username, api_id, api_hash) as client:
        client.loop.run_until_complete(authenticate(client))
        typer.echo(
            f"----------------Retrieving Entity from {channel_id} --------------"
        )
        client.loop.run_until_complete(RefreshInfoChannel(client, channel_id))


@app.command()
def SaveMessagesHistoryFromChannel(channel: str, use_virustotal: bool = True,limit_count: int = 0):
    """
    Save messages in database from a specific channel and save/update information about channel.\n
    --channel Channel to download messages and files. \n
    --use-virustotal Flag to deactivate the Virustotal analisys files, by default is True.\n
    --limit_count Option to specify a limit to download a total messages.
    
    """
    if not channel:
        typer.echo("Please, you must insert a channel/chat valid.")
    else:
        with TelegramClient(username, api_id, api_hash) as client:
            client.loop.run_until_complete(authenticate(client))
            channel_id = client.loop.run_until_complete(
                IsMemberOfChannel(client, channel)
            )

            if not channel_id:
                typer.echo("You aren't a member of the channel/chat")
                input_join = typer.confirm("Do you want join it?")
                if input_join:
                    client.loop.run_until_complete(
                        client(functions.channels.JoinChannelRequest(channel=channel))
                    )
                    typer.echo("You are a member now.")
                    channel_id = client.loop.run_until_complete(
                        IsMemberOfChannel(client, channel)
                    )
                else:
                    typer.echo("We cannot continue! Bye...")
                    raise typer.Abort()

            client.loop.run_until_complete(RefreshInfoChannel(client, channel_id))
            client.loop.run_until_complete(
                SaveHistoryMessages(client, channel, channel_id, use_virustotal,limit_count)
            )
        typer.echo("Finished!")

@app.command()
def UpdateRestrictedWordListChannel(channel_id:int, file_name: str = "RestrictedWordList.txt" ):
    """
    Update the word list about a channel.\n
        --channel Channel id to update the word list \n
        --file-name By default is RestrictedWordList.txt 
    """
    restricted_List = ReadRestrictedWordList(file_name)
            
    # Save in BBDD
    db.session.query(Channel).filter(Channel.id_channel == channel_id).update(
        {
         Channel.restricted_words: restricted_List}
    )
    db.session.commit()
    typer.echo("List of words updated!")
    

@app.command()
def JoinToPublicChannel(channel:str):
    """
    Join to a public channel.\n

    --channel Link(https://t.me/XYXYXY) or name(XYXYXY) about channel to leave.

    """
    try:
        #https://t.me/LibrosDesbordados
        if channel:
            with TelegramClient(username, api_id, api_hash) as client:
                client.loop.run_until_complete(authenticate(client))  
                total_dialogs = client.loop.run_until_complete(GetTotalDialogs(client))
                typer.echo(f"------------------------------")
                typer.echo(f"You are in {total_dialogs} channels.")
                typer.echo("The channel to join is: "+ channel)
                client.loop.run_until_complete(client(functions.channels.JoinChannelRequest(channel=channel)))
                typer.echo(typer.style(f"You are in {total_dialogs+1} channels now.", fg=typer.colors.BLUE, bold=True))
        else:
            typer.echo("Please, insert a correct link")
    except ChannelInvalidError as ex:
        typer.echo(typer.style("The channel is invalid.", fg=typer.colors.RED, bold=True))
    except ChannelPrivateError as ex:
        typer.echo(typer.style("The channel is private or you are banned.", fg=typer.colors.RED, bold=True))
    except ChannelsTooMuchError as ex:
        typer.echo(typer.style("You have joined too many channels/supergroups.", fg=typer.colors.RED, bold=True))
    except ValueError as ex:
        typer.echo(typer.style("The channel is invalid.", fg=typer.colors.RED, bold=True))

@app.command()
def LeaveChannel(channel:str):
    """
    Leave a channel.

    --channel Link(https://t.me/XYXYXY) or name(XYXYXY) about channel to leave.

    """
    try:
        if channel:
            with TelegramClient(username, api_id, api_hash) as client:
                client.loop.run_until_complete(authenticate(client))  
                total_dialogs = client.loop.run_until_complete(GetTotalDialogs(client))                
                typer.echo(f"------------------------------")
                typer.echo(f"You are in {total_dialogs} channels.")
                typer.echo("Channel to leave is: "+ channel)
                client.loop.run_until_complete(client(functions.channels.LeaveChannelRequest(channel = channel)))
                typer.echo(typer.style(f"You are in {total_dialogs-1} channels now.", fg=typer.colors.BLUE, bold=True))
        else:
            typer.echo("Please, insert a correct link")
    except ChannelInvalidError as ex:
        typer.echo(typer.style("The channel is invalid.", fg=typer.colors.RED, bold=True))
    except ChannelPrivateError as ex:
        typer.echo(typer.style("The channel is private or you are banned.", fg=typer.colors.RED, bold=True))
    except ChannelPublicGroupNaError as ex:
        typer.echo(typer.style("Channel/supergroup is not avaliable.", fg=typer.colors.RED, bold=True))
    except UserCreatorError as ex:
        typer.echo(typer.style("You can't leave this channel, because you're its creator.", fg=typer.colors.RED, bold=True))
    except UserNotParticipantError as ex:
        typer.echo(typer.style("The target user is not a member of the specified megagroup or channel.", fg=typer.colors.RED, bold=True))
    except ValueError as ex:
        typer.echo(typer.style("The channel is invalid.", fg=typer.colors.RED, bold=True))

async def SaveHistoryMessages(client: TelegramClient, channel: str, channel_id: int, use_virustotal: bool,limit_count:int):
    try:
        counter = 0
        counter_finish = False
        if channel and channel_id:
            typer.echo(
                f"----------------Retrieving Message History from {channel} --------------"
            )
            
            limit = 20
            if limit_count < 20:
                limit = limit_count
            messages_to_add = []
            urls_to_add = []
            id_last_msg = 0
            empty_channel = False

            #Get the last message id from telegram history
            last_message_history =  await client.get_messages(
                entity=channel,limit=1
            )
            last_id_msg_history = last_message_history[0].id

            channel_db = (
                db.session.query(Channel)
                .filter(Channel.id_channel == channel_id)
                .first()
            )
            if len(channel_db.messages) > 0:
                id_last_msg = channel_db.last_message_id

            id_msg_tmp = id_last_msg
            # Download messages by batches
            while not empty_channel and not counter_finish:
                async for message in client.iter_messages(
                    entity=channel,limit=limit, min_id=id_last_msg, reverse=True,
                ):

                    if type(message) == patched.Message and (message.message or message.media):
                        urls_to_add.extend(FindUrl(message.message))
                        msg = await MapperConversationToMessage(message)
                        if msg.id_media and msg.size_media < 20971520:
                            # Downloading file
                            typer.echo("Downloading document...")

                            file_name = await client.download_media(message, progress_callback=callback)

                            typer.echo(f"Document {file_name} downloaded.")                            

                            extension_file = os.path.splitext(file_name)[1]
                            if IsValidExtension(extension_file):
                                # Upload file to Diario
                                AnalyseDiarioDocuments(file_name, msg, diario_token, diario_secret)
                            elif use_virustotal:
                                # Upload file to Virustotal if flag is true
                                await AnalyseVirusTotalDocuments(file_name, msg,vt_token)
                            #Delete the file downloaded
                            if os.path.isfile(f"./{file_name}"):
                                os.remove(file_name)
                        messages_to_add.append(msg)
                        id_msg_tmp = message.id

                    elif type(message) == patched.MessageService:
                        id_msg_tmp = message.id
                        typer.echo("It's not a message.")

                counter += limit
                if counter >= limit_count:
                    counter_finish = True

                id_last_msg = id_msg_tmp    
                if id_last_msg == last_id_msg_history:
                    typer.echo("There aren't any more messages")
                    empty_channel = True

            typer.echo(str(len(messages_to_add)) + " new messages to add.")

            #Join new and old messages
            messages_to_add = extractJsonString(messages_to_add)
            messages_new = channel_db.messages
            messages_new.extend(messages_to_add)

            #Join new and old urls
            urls_to_add = MapperListToUrlsObject(urls_to_add)
            urls_to_add = AnalyseUrls(urls_to_add)
            urls_to_add = extractJsonString(urls_to_add)
            urls_new = channel_db.urls
            urls_new.extend(urls_to_add)

            restricted_List = ReadRestrictedWordList('RestrictedWordList.txt')
            

            # Save in BBDD
            db.session.query(Channel).filter(Channel.id_channel == channel_id).update(
                {Channel.messages: messages_new,
                 Channel.updated: datetime.now(),
                 Channel.last_message_id: id_last_msg,
                 Channel.urls: urls_new,
                 Channel.restricted_words: restricted_List}
            )
            db.session.commit()
            typer.echo("History Messages updated!")
        else:
            typer.echo("Please, insert a correct link")
    except ValueError as ex:
        typer.echo(
            typer.style(
                "The channel is invalid or there are an error. Try it later!",
                fg=typer.colors.RED,
                bold=True,
            )
        )

# Printing download progress
def callback(current, total):
    print('Downloaded', current, 'out of', total,'bytes: {:.2%}'.format(current / total))

async def SaveDialogs(client: TelegramClient, limit: int):
    me = await client.get_me()
    for dialog in await client.get_dialogs(limit=limit):
        SaveChannel(dialog,me.id)

def SaveChannel(dialog, current_user_id):
    try:
        channel = MapperDialogToChannel(dialog,current_user_id)
        db.session.add(channel)
        db.session.commit()
        typer.echo("Saved succesfully! Channel: " + channel.title)
    except (IntegrityError, InvalidRequestError):
        typer.echo(
            f"The channel {utils.get_display_name(dialog.entity)} with id {dialog.entity.id} is already in the database."
        )
        db.session.rollback()
        typer.echo(f"Trying to update it.")
        typer.echo(channel.id_channel)
        db.session.query(Channel).filter(
            Channel.id_channel == channel.id_channel
        ).update(
            {
                Channel.title: channel.title,
                Channel.verified: channel.verified,
                Channel.username: channel.username,
                Channel.date: channel.date,
                Channel.participants_count: channel.participants_count,
                Channel.access_hash: channel.access_hash,
                Channel.is_channel: channel.is_channel,
                Channel.updated: datetime.now(),
                Channel.current_user_id: current_user_id
            }
        )
        db.session.commit()
        typer.echo(
            f"The channel {utils.get_display_name(dialog.entity)} was UPDATED succesfully."
        )

async def RefreshInfoChannel(client: TelegramClient, channel_id: int):
    me = await client.get_me()
    
    for dialog in await client.get_dialogs():
        if dialog.entity.id == channel_id:
            SaveChannel(dialog,me.id)
            return channel_id
    return None

async def IsMemberOfChannel(client: TelegramClient, channel):
    if not channel.isnumeric():
        channel_info = await client.get_entity(channel)
        channel_id = channel_info.id
    else:
        channel_id = int(channel)

    for dialog in await client.get_dialogs():
        if dialog.entity.id == channel_id:
            return channel_id
    return None

async def authenticate(client: TelegramClient):
    try:
        await client.start()
        # Ensure you're authorized
        if await client.is_user_authorized() == False:
                await client.send_code_request(phone)
                code = typer.prompt("Enter the code that you received in your phone: ")
                await client.sign_in(phone, code)
    except SessionPasswordNeededError:
            pdw = typer.prompt("Enter the password: ")
            await client.sign_in(password=pdw)
    typer.echo(
    typer.style("Your credentials are corrects!", fg=typer.colors.GREEN, bold=True))
    me = await client.get_me()
    return me

async def GetTotalDialogs(client: TelegramClient):
    dialogs = await  client.get_dialogs()
    return len(dialogs)

if __name__ == "__main__":
    typer.echo("Started!")
    try:
        db.Base.metadata.create_all(db.engine)
        app()
    except OperationalError:
        typer.echo(
        typer.style("Error connecting with database, verify configuration.", fg=typer.colors.RED, bold=True)
        )
        typer.Abort()
    except PhoneNumberInvalidError:
        typer.echo(
        typer.style("Please, enter the country code with the phone number, p.e. an Spanish number +34XXXXXXXXX", fg=typer.colors.RED, bold=True))
        typer.Abort()
        
    
