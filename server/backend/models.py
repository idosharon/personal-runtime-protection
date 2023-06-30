"""
    File: models.py
    Description: Database models for the backend server, using SQLAlchemy.
"""
from .consts import db
from sqlalchemy import text

# create db model
class Event(db.Model):
    """
    Represents a single event in the system.
    """
    id = db.Column(db.Integer, primary_key=True)

    timestamp = db.Column(db.BigInteger, nullable=False)
    syscall = db.Column(db.String(10), nullable=False)

    pid = db.Column(db.Integer, nullable=False)
    ppid = db.Column(db.Integer, nullable=False)
    uid = db.Column(db.Integer, nullable=False)

    process = db.Column(db.String(50), nullable=False)
    value = db.Column(db.String(50), nullable=False)

    def __init__(self, timestamp: int, syscall: str, pid: int, ppid: int, uid: int, process: str, value: str):
        self.timestamp = timestamp
        self.syscall = syscall
        self.pid = pid
        self.ppid = ppid
        self.uid = uid
        self.process = process
        self.value = value

    def __repr__(self):
        return '<Event %r>' % self.id
    
    def serialize(self):
        return {
            'id': self.id,
            'timestamp': self.timestamp,
            'syscall': self.syscall,
            'pid': self.pid,
            'ppid': self.ppid,
            'uid': self.uid,
            'process': self.process,
            'value': self.value
        }

class Rule(db.Model):
    """
    Represents a search rule for events.
    """
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(50), nullable=False)
    description = db.Column(db.String(200), nullable=False)
    code = db.Column(db.String(10), nullable=False)
    level = db.Column(db.String(10), nullable=False)
    sql_code = db.Column(db.String(200), nullable=False)

    def __init__(self, title: str, description: str, code: str, level: str, sql_code: str):
        self.title = title
        self.description = description
        self.code = code
        self.level = level
        self.sql_code = sql_code
    
    def __repr__(self):
        return '<Rule %r>' % self.id
    
    def serialize(self): 
        return {
            'id': self.id,
            'title': self.title,
            'description': self.description,
            'code': self.code,
            'level': self.level,
            'sql_code': self.sql_code
        }
    
    def run(self):
        """
        Run the rule on the database
        """
        return db.session.execute(text(self.sql_code)).fetchall()

