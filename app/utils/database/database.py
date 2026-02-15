from sqlalchemy import create_engine, MetaData
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.automap import automap_base
import logging

logging.basicConfig(level=logging.DEBUG)

class Database:
    def __init__(self, url: str, tables: list):
        self.url = url
        self.tables = tables
        self.Base = automap_base()
        self.engine = None
        self.SessionLocal = None

    def init_database(self):
        try:
            self.engine = create_engine(self.url, echo=True, pool_pre_ping=True, pool_recycle=1800, pool_timeout=30)
            metadata = MetaData()
            metadata.reflect(self.engine, only=self.tables)
            self.Base.prepare(self.engine, reflect=True)
            self.SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=self.engine)
        except Exception as e:
            logging.critical(f"Cannot Access DB {self.url}: {e}")

    def return_tables(self):
        return self.Base.classes.keys()

    def create_model(self, table: str):
        try:
            return getattr(self.Base.classes, table)
        except AttributeError:
            logging.error(f"Table '{table}' not found in database {self.url}")
            return None
        
    def get_db(self):
        db = self.SessionLocal()
        try:
            yield db
        finally:
            db.close()