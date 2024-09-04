from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
import configparser


config = configparser.ConfigParser()
config.read("config.ini")

connection_string = config["Postgre"]["connection_string"]

engine = create_engine(connection_string)
Session = sessionmaker(bind=engine)
session = Session()

Base = declarative_base()